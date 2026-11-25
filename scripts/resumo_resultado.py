#!/usr/bin/env python3
"""
Fase 2 — Resumo da aplicação (ou da simulação).

Junta <pasta>/*.json (um por servidor) em <saida.md> e imprime no log.
Em simulação (--check) mostra, por servidor, cada pacote: versão atual → versão nova
(Linux) ou cada atualização do Windows Update que seria instalada (Windows, W2).

    python scripts/resumo_resultado.py [pasta=out/resultado] [saida=out/resultado.md]
"""

from __future__ import annotations

import glob
import json
import os
import re
import sys

# pacotes cuja troca exige reboot (headers/devel/tools NÃO exigem)
_RE_KERNEL_REBOOT = re.compile(r"^(linux-image-|linux-modules-|kernel(-core|-modules)?[.\s])")


def sim(v) -> bool:
    return str(v).lower() == "true"


def main() -> int:
    pasta = sys.argv[1] if len(sys.argv) > 1 else "out/resultado"
    saida = sys.argv[2] if len(sys.argv) > 2 else "out/resultado.md"
    arquivos = sorted(glob.glob(os.path.join(pasta, "*.json")))
    resultados = []
    for a in arquivos:
        with open(a, encoding="utf-8") as f:
            resultados.append(json.load(f))

    simulacao = bool(resultados) and all(sim(r.get("simulacao")) for r in resultados)
    windows = bool(resultados) and all(r.get("sistema") == "windows" for r in resultados)
    titulo = ("# Simulação de patch — nada foi alterado" if simulacao
              else "# Resultado da aplicação de patch")
    if windows:
        titulo += " (Windows · W2)"
    col_itens, col_versao, col_espaco = (("Atualizações", "Build", "Disco livre (GB)") if windows
                                         else ("Pacotes", "Kernel", "/boot livre (MB)"))
    linhas = [
        titulo,
        "",
        f"| Servidor | Ambiente | Status | {col_itens} | {col_versao} antes | {col_versao} depois | Reboot | {col_espaco} | Serviços que não voltaram | Erro |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]
    falhas = 0
    for r in resultados:
        if r.get("status") == "falha":
            falhas += 1
        n_pacotes = len(r.get("mudancas_previstas") or []) if simulacao else len(r.get("pacotes_atualizados") or [])
        previsto = sim(r.get("reboot_previsto")) or any(_RE_KERNEL_REBOOT.search(m)
                                                         for m in r.get("mudancas_previstas") or [])
        reboot = "previsto" if simulacao and previsto else (
            "sim" if sim(r.get("reboot")) else ("pendente" if sim(r.get("reboot_pendente")) else "—"))
        espaco = r.get("disco_livre_gb") if r.get("sistema") == "windows" else r.get("boot_livre_mb")
        linhas.append(
            f"| {r.get('host')} | {r.get('ambiente', '')} | {r.get('status')} | {n_pacotes} | "
            f"{r.get('kernel_antes', '')} | {r.get('kernel_depois', '')} | {reboot} | "
            f"{espaco or '—'} | {', '.join(r.get('servicos_parados') or []) or '—'} | "
            f"{r.get('erro', '')} |"
        )
    if not resultados:
        linhas.append("| — | — | nenhum host processado | — | — | — | — | — | — | — |")

    for r in resultados:
        mud = r.get("mudancas_previstas") or []
        if mud:
            oque = ("atualizações que seriam instaladas" if windows else "pacotes que seriam atualizados") if simulacao \
                else ("atualizações disponíveis" if windows else "pacotes e versões")
            linhas += ["", f"## {r.get('host')} — {oque} ({len(mud)})",
                       "", "```"] + mud + ["```"]

    rem = [(r.get("host"), r.get("kernels_antigos_removidos")) for r in resultados if r.get("kernels_antigos_removidos")]
    if rem:
        titulo_rem = "## Kernels antigos que seriam removidos" if simulacao else "## Kernels antigos removidos"
        linhas += ["", titulo_rem, ""] + [f"- **{h}**: {' '.join(k)}" for h, k in rem]

    terc = [(r.get("host"), t) for r in resultados for t in (r.get("terceiros") or [])]
    if terc:
        linhas += ["", "## Softwares de terceiros (W2b)", "",
                   "| Servidor | Produto | Detecções | Instalado | Versão antes | Versão depois | Execução |", "|---|---|---|---|---|---|---|"]
        for h, t in terc:
            ex = t.get("execucao") or {}
            exec_txt = (f"download {ex.get('download')}, instalação {ex.get('instalacao')}" if ex
                        else ("simulação" if simulacao else "—"))
            linhas.append(f"| {h} | {t.get('produto')} | {t.get('deteccoes')} | {'sim' if sim(t.get('instalado')) else 'não'} | "
                          f"{t.get('antes') or '—'} | {t.get('depois') or '—'} | {exec_txt} |")

    avisos = [(r.get("host"), a) for r in resultados for a in (r.get("avisos") or [])]
    if avisos:
        linhas += ["", "## ⚠️ Avisos", ""] + [f"- **{h}**: {a}" for h, a in avisos]

    kern = [r for r in resultados if r.get("kernel_mais_novo_instalado")]
    if kern:
        linhas += ["", "## Kernel e GRUB", "", "| Servidor | Em uso | Mais novo instalado | GRUB |", "|---|---|---|---|"]
        linhas += [f"| {r.get('host')} | {r.get('kernel_depois') or r.get('kernel_antes', '')} | "
                   f"{r.get('kernel_mais_novo_instalado')} | {r.get('grub', '')} |" for r in kern]

    falhos = [r for r in resultados if r.get("servicos_falhos_antes") or r.get("servicos_falhos_novos")]
    if falhos:
        linhas += ["", "## Serviços com falha", "",
                   "| Servidor | Já falhavam ANTES (não é da esteira) | Passaram a falhar DEPOIS |", "|---|---|---|"]
        linhas += [f"| {r.get('host')} | {', '.join(r.get('servicos_falhos_antes') or []) or '—'} | "
                   f"{', '.join(r.get('servicos_falhos_novos') or []) or '—'} |" for r in falhos]

    if simulacao:
        linhas += ["", "Simulação: nenhum pacote foi instalado e nenhum servidor reiniciou. "
                       "Para aplicar de verdade, rode de novo com **🧪 Simular** desmarcado."]
    else:
        linhas += ["", "A confirmação de que a vulnerabilidade fechou vem do próximo scan do Cloud Agent "
                       "(métrica de acompanhamento)."]
    md = "\n".join(linhas) + "\n"
    os.makedirs(os.path.dirname(saida) or ".", exist_ok=True)
    with open(saida, "w", encoding="utf-8") as f:
        f.write(md)
    print(md)
    return 1 if falhas else 0


if __name__ == "__main__":
    sys.exit(main())
