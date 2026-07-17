#!/usr/bin/env python3
"""
ssl_expiry_watchdog.py
=======================
AI SSL/TLS Expiry Watchdog — verifica a validade dos certificados de uma
lista de domínios e usa a API GRATUITA da Groq (Llama 3.3 70B) para gerar
um resumo priorizado, pronto para colar no Slack ou e-mail do time.

Por que isso existe: certificado vencido ainda é uma das causas mais bobas
e mais comuns de outage em produção. Esse script roda sozinho no crontab,
checa todos os domínios que importam e só te avisa quando algo precisa de
atenção — com prioridade já definida pela IA, não só uma lista crua de datas.

O que ele faz:
  1. Conecta em cada domínio (porta 443) e lê a data de expiração real do
     certificado (não depende de nenhuma API paga, é TLS puro).
  2. Calcula quantos dias faltam para vencer.
  3. Manda a lista para a IA, que devolve: prioridade de ação, quais
     domínios são realmente urgentes, e uma mensagem pronta pro Slack.
  4. Se nada estiver perto de vencer, ele nem chama a IA — só imprime OK
     e sai (economiza a cota grátis).

Uso manual:
    export GROQ_API_KEY="gsk_..."
    python ssl_expiry_watchdog.py --domains meusite.com,api.meusite.com,app.meusite.com

    # Só considerar urgente abaixo de 15 dias
    python ssl_expiry_watchdog.py --domains meusite.com --threshold-days 15

    # Gravar o resumo em arquivo em vez de imprimir (bom para cron)
    python ssl_expiry_watchdog.py --domains meusite.com --out /var/log/ssl/latest.md

Rodando no crontab (todo dia às 8h, checando 3 domínios):
    0 8 * * * GROQ_API_KEY="gsk_..." /usr/bin/python3 /caminho/ssl_expiry_watchdog.py \\
        --domains meusite.com,api.meusite.com,app.meusite.com \\
        --out /var/log/ssl/latest.md >> /var/log/ssl/cron.log 2>&1

Requisitos:
    pip install groq --break-system-packages
"""

import argparse
import socket
import ssl
import sys
from datetime import datetime, timezone

try:
    from groq import Groq
except ImportError:
    sys.exit("Instale a dependência primeiro: pip install groq")

MODEL = "llama-3.3-70b-versatile"  # modelo grátis na Groq

SYSTEM_PROMPT = """Você é um engenheiro de SRE/DevOps sênior responsável por certificados TLS.
Dada uma lista de domínios com seus dias restantes até o vencimento do certificado,
responda SEMPRE no seguinte formato, em português, de forma direta:

## Prioridade
Ordene os domínios do mais urgente para o menos urgente.

## Recomendação
Para cada domínio com menos de 30 dias, diga o que fazer (renovar, checar
auto-renovação, checar se é wildcard usado por outros serviços).

## Resumo para o time
Uma mensagem curta (2-3 frases), pronta para colar no Slack, resumindo a
situação geral e a ação mais urgente.

Se todos os domínios estiverem com validade tranquila (> 30 dias), diga isso
em uma frase e não invente urgência."""


def get_cert_expiry(domain: str, port: int = 443, timeout: float = 5.0):
    """Conecta via TLS e retorna a data de expiração (UTC) do certificado."""
    ctx = ssl.create_default_context()
    with socket.create_connection((domain, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
            cert = ssock.getpeercert()
    expiry_str = cert["notAfter"]  # ex: 'Jan 20 12:00:00 2027 GMT'
    expiry = datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z").replace(
        tzinfo=timezone.utc
    )
    return expiry


def check_domains(domains: list[str]) -> list[dict]:
    results = []
    now = datetime.now(timezone.utc)
    for domain in domains:
        domain = domain.strip()
        if not domain:
            continue
        try:
            expiry = get_cert_expiry(domain)
            days_left = (expiry - now).days
            results.append(
                {
                    "domain": domain,
                    "expiry": expiry.isoformat(),
                    "days_left": days_left,
                    "error": None,
                }
            )
        except Exception as exc:
            results.append(
                {"domain": domain, "expiry": None, "days_left": None, "error": str(exc)}
            )
    return results


def analyze(results: list[dict]) -> str:
    client = Groq()  # lê GROQ_API_KEY do ambiente

    lines = []
    for r in results:
        if r["error"]:
            lines.append(f"- {r['domain']}: ERRO ao checar ({r['error']})")
        else:
            lines.append(f"- {r['domain']}: vence em {r['days_left']} dias ({r['expiry']})")
    payload = "\n".join(lines)

    response = client.chat.completions.create(
        model=MODEL,
        max_tokens=700,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": f"Domínios verificados:\n\n{payload}"},
        ],
    )
    return response.choices[0].message.content


def main():
    parser = argparse.ArgumentParser(
        description="Watchdog de expiração de certificados TLS com IA (Groq)."
    )
    parser.add_argument(
        "--domains",
        required=True,
        help="Lista de domínios separados por vírgula (ex: a.com,b.com)",
    )
    parser.add_argument(
        "--threshold-days",
        type=int,
        default=30,
        help="Só chama a IA se algum domínio estiver abaixo deste número de dias (padrão: 30)",
    )
    parser.add_argument(
        "--out",
        help="Grava o resultado neste arquivo em vez de imprimir (ideal para cron)",
    )

    args = parser.parse_args()
    domains = args.domains.split(",")

    results = check_domains(domains)

    urgent = [
        r for r in results
        if r["error"] or (r["days_left"] is not None and r["days_left"] <= args.threshold_days)
    ]

    timestamp = datetime.now(timezone.utc).isoformat()

    if not urgent:
        msg = f"[{timestamp}] Todos os {len(results)} domínios com validade > {args.threshold_days} dias. Tudo OK, pulando chamada à IA."
        print(msg)
        if args.out:
            with open(args.out, "a") as f:
                f.write(msg + "\n")
        return

    print(f"Encontrado(s) {len(urgent)} domínio(s) que precisam de atenção. Consultando IA...\n")
    result = analyze(results)

    if args.out:
        with open(args.out, "a") as f:
            f.write(f"\n---\n### Checagem em {timestamp}\n\n{result}\n")
        print(f"Resultado gravado em {args.out}")
    else:
        print(result)


if __name__ == "__main__":
    main()
