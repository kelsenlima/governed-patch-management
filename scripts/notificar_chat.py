#!/usr/bin/env python3
"""
Aviso no Google Chat ao fim de cada execução de patch (Linux ou Windows, simulação ou real).

    python scripts/notificar_chat.py <pasta_resultado> "<rótulo>"
    ex.: python scripts/notificar_chat.py out/resultado-windows "produção · Windows"

O webhook vem SÓ da variável de ambiente PATCH_CHAT_WEBHOOK (variável secreta no
Azure DevOps, mapeada no step). Nunca é impresso no log. Sem webhook, não faz nada.
Nunca falha o job: erro de envio vira aviso no log (sai sempre com 0).
Texto com *negrito*, emojis e link <url|texto>.
"""

from __future__ import annotations

import glob
import json
import os
import sys
import urllib.error
import urllib.request

LIMITE_LINHAS_SERVIDOR = 25     # servidores listados um a um; acima disso, só os com problema
LIMITE_AVISOS = 8


def sim(v) -> bool:
    return str(v).lower() == "true"


def link_run() -> str:
    base = os.environ.get("SYSTEM_COLLECTIONURI", "").rstrip("/")
    projeto = os.environ.get("SYSTEM_TEAMPROJECT", "")
    build = os.environ.get("BUILD_BUILDID", "")
    if not (base and projeto and build):
        return ""
    return f"{base}/{urllib.request.quote(projeto)}/_build/results?buildId={build}&view=results"


def linha_servidor(r: dict, simulacao: bool) -> str:
    host = r.get("host", "?")
    status = r.get("status", "?")
    windows = r.get("sistema") == "windows"
    if status == "falha":
        return f"❌ *{host}* — falha: {str(r.get('erro', ''))[:220]}"
    itens = len(r.get("mudancas_previstas") or []) if simulacao else len(r.get("pacotes_atualizados") or [])
    rotulo_itens = "atualização(ões)" if windows else "pacote(s)"
    partes = [f"{itens} {rotulo_itens}" + (" previstas" if simulacao else "")]
    antes, depois = r.get("kernel_antes", ""), r.get("kernel_depois", "")
    if antes and depois and antes != depois:
        partes.append(f"{'build' if windows else 'kernel'} {antes} → {depois}")
    if sim(r.get("reboot")):
        partes.append("🔁 reiniciou")
    elif sim(r.get("reboot_pendente")):
        partes.append("reboot pendente")
    for t in r.get("terceiros") or []:
        if t.get("depois") and t.get("antes") != t.get("depois"):
            partes.append(f"{t.get('produto')} {t.get('antes') or '—'} → {t.get('depois')}")
    parados = r.get("servicos_parados") or []
    if parados:
        partes.append("⚠️ não voltaram: " + ", ".join(parados)[:120])
    icone = "🧪" if simulacao else "✅"
    return f"{icone} *{host}* — " + " · ".join(partes)


def montar(pasta: str, rotulo: str) -> str | None:
    resultados = []
    for a in sorted(glob.glob(os.path.join(pasta, "*.json"))):
        try:
            with open(a, encoding="utf-8") as f:
                resultados.append(json.load(f))
        except (OSError, ValueError) as e:
            print(f"##[warning]Resultado ilegível ({a}): {e}")
    if not resultados:
        return None

    simulacao = all(sim(r.get("simulacao")) for r in resultados)
    falhas = [r for r in resultados if r.get("status") == "falha"]
    reiniciaram = [r for r in resultados if sim(r.get("reboot"))]
    avisos = [(r.get("host"), a) for r in resultados for a in (r.get("avisos") or [])]

    cab = "🧪 *Simulação de patch*" if simulacao else "🛠️ *Patch aplicado*"
    linhas = [f"{cab} · {rotulo}",
              f"*{len(resultados)} servidor(es)* · ✅ {len(resultados) - len(falhas)} ok · ❌ {len(falhas)} com falha"
              + ("" if simulacao else f" · 🔁 {len(reiniciaram)} reiniciaram"),
              ""]

    lista = resultados if len(resultados) <= LIMITE_LINHAS_SERVIDOR else falhas
    linhas += [linha_servidor(r, simulacao) for r in lista]
    if len(lista) < len(resultados):
        linhas.append(f"… e mais {len(resultados) - len(lista)} servidor(es) sem falha (detalhe na run)")

    if avisos:
        linhas += ["", f"*⚠️ Avisos ({len(avisos)})*"]
        linhas += [f"• {h}: {str(a)[:200]}" for h, a in avisos[:LIMITE_AVISOS]]
        if len(avisos) > LIMITE_AVISOS:
            linhas.append(f"• … mais {len(avisos) - LIMITE_AVISOS} na run")

    linhas.append("")
    linhas.append("Nada foi alterado nos servidores." if simulacao
                  else "A confirmação de que as vulnerabilidades fecharam vem do próximo scan (relatório de métricas).")
    url = link_run()
    if url:
        linhas.append(f"🔗 <{url}|Abrir a execução no Azure DevOps>")
    return "\n".join(linhas)


def main() -> int:
    pasta = sys.argv[1] if len(sys.argv) > 1 else "out/resultado"
    rotulo = sys.argv[2] if len(sys.argv) > 2 else "patch"
    webhook = os.environ.get("PATCH_CHAT_WEBHOOK", "").strip()
    # variável não criada no Azure DevOps chega como o próprio texto "$(PATCH_CHAT_WEBHOOK)"
    if not webhook.startswith("https://chat.googleapis.com/"):
        print("Google Chat: PATCH_CHAT_WEBHOOK não configurada — aviso não enviado.")
        return 0

    texto = montar(pasta, rotulo)
    if not texto:
        print("Google Chat: nenhum resultado em " + pasta + " — aviso não enviado.")
        return 0

    corpo = json.dumps({"text": texto}).encode("utf-8")
    req = urllib.request.Request(webhook, data=corpo, method="POST",
                                 headers={"Content-Type": "application/json; charset=UTF-8"})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            print(f"Google Chat: aviso enviado (HTTP {resp.status}).")
    except urllib.error.HTTPError as e:
        print(f"##[warning]Google Chat: envio falhou (HTTP {e.code}). Conferir PATCH_CHAT_WEBHOOK.")
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        print(f"##[warning]Google Chat: envio falhou ({type(e).__name__}). O agente alcança chat.googleapis.com?")
    print("--- mensagem ---")
    print(texto)
    return 0


if __name__ == "__main__":
    sys.exit(main())
