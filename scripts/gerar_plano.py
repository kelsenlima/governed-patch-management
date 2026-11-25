#!/usr/bin/env python3
"""
Fase 1 — Plano.

Lê out/deteccoes.json, aplica policy/policy.yml e o inventário e gera:
  out/plano.json   → consumido pelo playbook de aplicação (Fase 2)
  out/plano.csv    → uma linha por pacote/QID (para auditoria e planilha)
  out/resumo.md    → resumo publicado na tela do pipeline

Nenhum servidor é alterado nesta etapa.
"""

from __future__ import annotations

import argparse
import csv
import re
import json
import os
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import qualys_lib as q  # noqa: E402

ORDEM = {"AUTO": 1, "KERNEL": 2, "JANELA": 3, "REMOVER": 4, "MANUAL": 5, "WINDOWS": 6}


def _chave_versao(v: str) -> tuple:
    """Chave de ordenação para versões tipo 6.1.140-1 / 6.8.0-1073 / 1:2.3 (só os números importam)."""
    return tuple(int(x) for x in re.findall(r"\d+", v or ""))


def rota_do_pacote(nome: str, ambiente: str, politica: dict) -> tuple[str, str]:
    """Rota de um pacote, já ajustada ao ambiente. Retorna (rota, motivo)."""
    regras = politica.get("ambientes", {}).get(ambiente, {"protegidos": "JANELA", "kernel": "JANELA"})
    if q.casa_padrao(nome, politica.get("pacotes_remover", [])):
        return "REMOVER", "pacote inseguro (remover)"
    if q.casa_padrao(nome, politica.get("pacotes_kernel", [])):
        return regras.get("kernel", "JANELA"), "kernel (exige reboot)"
    if q.casa_padrao(nome, politica.get("pacotes_protegidos", [])):
        return regras.get("protegidos", "JANELA"), "pacote protegido"
    return "AUTO", "pacote comum"


def gerar(deteccoes: list[dict], politica: dict, mapa_inv: dict, mapa_win: dict | None = None) -> dict:
    hosts: dict[str, dict] = {}
    windows: dict[str, dict] = {}
    linhas_csv: list[dict] = []
    fora_inventario: Counter = Counter()
    fora_conhecidos: Counter = Counter()
    conhecidos = {str(c.get("host", "")).lower(): c.get("motivo", "")
                  for c in politica.get("fora_inventario_conhecidos") or [] if c.get("host")}
    mapa_win = mapa_win or {}

    for d in deteccoes:
        base = {
            "qid": d["qid"],
            "severidade": d["severidade"],
            "categoria": d.get("categoria", ""),
            "titulo": d.get("titulo", ""),
            "ip": d["ip"],
        }
        inv = mapa_inv.get(d["ip"])
        nome_qualys = (d.get("dns") or d.get("netbios") or d["ip"]).split(".")[0].lower()

        # ---- Windows (W1): só plano, classificado por tipo de correção
        e_windows = "windows" in (d.get("so") or "").lower()
        inv_win = mapa_win.get(nome_qualys) or mapa_win.get((d.get("netbios") or "").lower())
        if e_windows and inv_win:
            c = q.classificar_windows(d.get("titulo", ""), d.get("categoria", ""), d.get("resultado", ""))
            w = windows.setdefault(inv_win["host"], {
                "ip": d["ip"], "ambiente": inv_win["ambiente"], "so": d.get("so", ""),
                "criticas": 0, "altas": 0, "por_classe": {k: 0 for k in q.CLASSES_WINDOWS},
                "kbs": [], "reboot_pendente": False, "itens": [],
            })
            w["criticas" if d["severidade"] == 5 else "altas"] += 1
            w["por_classe"][c["classe"]] += 1
            w["kbs"] = sorted(set(w["kbs"]) | set(c["kbs"]))
            w["reboot_pendente"] = w["reboot_pendente"] or c["reboot_pendente"]
            w["itens"].append({"qid": d["qid"], "severidade": d["severidade"], "classe": c["classe"],
                               "titulo": d.get("titulo", ""), "kbs": c["kbs"], "evidencia": c["evidencia"]})
            linhas_csv.append({**base, "host": inv_win["host"], "ambiente": inv_win["ambiente"],
                               "pacote": " ".join(c["kbs"]), "versao_instalada": "", "versao_exigida": "",
                               "rota": "WINDOWS", "motivo": c["classe"]})
            continue

        if not inv:
            motivo_conhecido = conhecidos.get(str(nome_qualys).lower()) or conhecidos.get(str(d["ip"]).lower())
            if motivo_conhecido is not None:
                fora_conhecidos[f"{nome_qualys} ({d['ip']}) — {motivo_conhecido}"] += 1
            else:
                fora_inventario[f"{nome_qualys} ({d['ip']})"] += 1
            linhas_csv.append({**base, "host": nome_qualys, "ambiente": "", "pacote": "", "versao_instalada": "",
                               "versao_exigida": "", "rota": "MANUAL",
                               "motivo": motivo_conhecido or "host fora do inventário Ansible"})
            continue

        h = hosts.setdefault(inv["host"], {
            "ip": d["ip"], "ambiente": inv["ambiente"], "so": d.get("so", ""),
            "pacotes": {r: [] for r in ORDEM if r != "MANUAL"},
            "manual": [], "qids": [], "criticas": 0, "altas": 0, "kernel_exige_janela": False,
            "det_por_rota": {}, "kernel_instalado": "", "kernel_exigido": "",
        })
        h["qids"].append(d["qid"])
        h["criticas" if d["severidade"] == 5 else "altas"] += 1

        pacotes = d.get("pacotes") or []
        if "windows" in (d.get("so") or "").lower():
            motivo = "Windows (fora desta esteira)"
            pacotes = []
        else:
            motivo = "Qualys não informou pacote/versão"

        if not pacotes:
            h["manual"].append({"qid": d["qid"], "titulo": d.get("titulo", ""), "motivo": motivo})
            h["det_por_rota"]["MANUAL"] = h["det_por_rota"].get("MANUAL", 0) + 1
            linhas_csv.append({**base, "host": inv["host"], "ambiente": inv["ambiente"], "pacote": "",
                               "versao_instalada": "", "versao_exigida": "", "rota": "MANUAL", "motivo": motivo})
            continue

        rotas_det = []
        for p in pacotes:
            rota, mot = rota_do_pacote(p["nome"], inv["ambiente"], politica)
            rotas_det.append("KERNEL" if mot.startswith("kernel") and rota != "JANELA" else rota)
            # Kernel fica sempre na lista KERNEL (a role trata metapacotes + reboot);
            # a coluna "rota" mostra se, neste ambiente, ele exige janela.
            destino = "KERNEL" if mot.startswith("kernel") else rota
            if p["nome"] not in h["pacotes"][destino]:
                h["pacotes"][destino].append(p["nome"])
            if destino == "KERNEL":
                h["kernel_exige_janela"] = rota == "JANELA"
                # maior versão exigida pelo Qualys (comparação natural: números separados)
                if p.get("exigida") and _chave_versao(p["exigida"]) > _chave_versao(h["kernel_exigido"]):
                    h["kernel_exigido"] = p["exigida"]
                    h["kernel_instalado"] = p.get("instalada", "")
            linhas_csv.append({**base, "host": inv["host"], "ambiente": inv["ambiente"], "pacote": p["nome"],
                               "versao_instalada": p.get("instalada", ""), "versao_exigida": p.get("exigida", ""),
                               "rota": rota, "motivo": mot})
        final = max(rotas_det, key=lambda r: ORDEM[r])
        if final == "JANELA" and all(r == "JANELA" for r in rotas_det) and any(
            q.casa_padrao(p["nome"], politica.get("pacotes_kernel", [])) for p in pacotes
        ):
            final = "JANELA_KERNEL"
        h["det_por_rota"][final] = h["det_por_rota"].get(final, 0) + 1

    for h in hosts.values():
        h["qids"] = sorted(set(h["qids"]))
        h["reboot_necessario"] = bool(h["pacotes"]["KERNEL"])
        for r in h["pacotes"]:
            h["pacotes"][r].sort()

    return {
        "gerado_em": datetime.now(timezone.utc).isoformat(),
        "hosts": dict(sorted(hosts.items(), key=lambda kv: -len(kv[1]["qids"]))),
        "windows": dict(sorted(windows.items(), key=lambda kv: -(kv[1]["criticas"] + kv[1]["altas"]))),
        "fora_inventario": dict(fora_inventario.most_common()),
        "fora_inventario_conhecidos": dict(fora_conhecidos.most_common()),
        "linhas": linhas_csv,
    }


def resumo_markdown(plano: dict) -> str:
    rotulos = [
        ("AUTO", "Corrige sozinho (Fase 2)"),
        ("KERNEL", "Kernel + reboot (não-produção)"),
        ("JANELA_KERNEL", "Kernel + reboot em produção (precisa de janela)"),
        ("JANELA", "Pacote protegido (precisa de janela em produção)"),
        ("REMOVER", "Remover pacote inseguro (aprovação)"),
        ("MANUAL", "Fora da esteira (ver motivo no CSV)"),
    ]
    tot = {k: 0 for k, _ in rotulos}
    for h in plano["hosts"].values():
        for k, v in h["det_por_rota"].items():
            tot[k] = tot.get(k, 0) + v
    fora = sum(plano["fora_inventario"].values())
    total = sum(tot.values())
    linhas = [
        "# Plano de patch — Qualys (Fase 1: somente leitura)",
        "",
        f"Gerado em {plano['gerado_em']}",
        "",
        f"**{total} vulnerabilidades abertas (críticas + altas)** em **{len(plano['hosts'])} servidores do inventário**"
        + (f" · {fora} em servidores fora do inventário." if fora else "."),
        "",
        "## Quantas vulnerabilidades cada ação fecha",
        "",
        "| Ação | Vulnerabilidades | % |",
        "|---|---|---|",
    ]
    for k, desc in rotulos:
        if tot.get(k):
            linhas.append(f"| {desc} | {tot[k]} | {round(100 * tot[k] / total) if total else 0}% |")
    linhas += [
        "",
        "## Por servidor (vulnerabilidades)",
        "",
        "| Servidor | Ambiente | Críticas | Altas | Auto | Kernel | Kernel c/ janela | Protegido c/ janela | Remover | Manual |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]
    for nome, h in plano["hosts"].items():
        d = h["det_por_rota"]
        linhas.append(
            f"| {nome} | {h['ambiente']} | {h['criticas']} | {h['altas']} | {d.get('AUTO', 0)} | {d.get('KERNEL', 0)} | "
            f"{d.get('JANELA_KERNEL', 0)} | {d.get('JANELA', 0)} | {d.get('REMOVER', 0)} | {d.get('MANUAL', 0)} |"
        )
    win = plano.get("windows") or {}
    if win:
        tot_w = {k: sum(h["por_classe"].get(k, 0) for h in win.values()) for k in q.CLASSES_WINDOWS}
        total_w = sum(tot_w.values())
        linhas += [
            "",
            "## Windows Server (W1 plano · W2/W2b patch)",
            "",
            f"**{total_w} vulnerabilidades (críticas + altas)** em **{len(win)} servidores Windows**. "
            "A aplicação é do job Windows (W2: Windows Update · W2b: terceiros e Office).",
            "",
            "| Tipo de correção | Vulnerabilidades | % |",
            "|---|---|---|",
        ]
        for k, desc in q.CLASSES_WINDOWS.items():
            if tot_w.get(k):
                linhas.append(f"| {desc} | {tot_w[k]} | {round(100 * tot_w[k] / total_w) if total_w else 0}% |")
        linhas += [
            "",
            "| Servidor | Ambiente | Críticas | Altas | KB Windows | Microsoft | Terceiros | Config | KBs apontados | Reboot pendente |",
            "|---|---|---|---|---|---|---|---|---|---|",
        ]
        for nome, h in win.items():
            c = h["por_classe"]
            kbs = ", ".join(h["kbs"][:6]) + (f" (+{len(h['kbs']) - 6})" if len(h["kbs"]) > 6 else "")
            linhas.append(
                f"| {nome} | {h['ambiente']} | {h['criticas']} | {h['altas']} | {c.get('WINDOWS_UPDATE', 0)} | "
                f"{c.get('MICROSOFT_APP', 0)} | {c.get('TERCEIROS', 0)} | {c.get('CONFIG', 0)} | {kbs or '—'} | "
                f"{'sim' if h['reboot_pendente'] else '—'} |"
            )
        # top softwares (terceiros + Microsoft fora do WU) — onde está o volume
        cont: Counter = Counter()
        for h in win.values():
            for it in h["itens"]:
                if it["classe"] in ("TERCEIROS", "MICROSOFT_APP"):
                    cont[it["titulo"][:90] or f"QID {it['qid']}"] += 1
        if cont:
            linhas += ["", "**Softwares fora do Windows Update que mais aparecem:**", ""]
            linhas += [f"- {t} — {n}" for t, n in cont.most_common(10)]

    kern = [(n, h) for n, h in plano["hosts"].items() if h.get("kernel_exigido")]
    if kern:
        linhas += ["", "## Kernel: instalado × exigido pelo Qualys", "",
                   "| Servidor | Ambiente | Instalado (Qualys) | Exigido (Qualys) |", "|---|---|---|---|"]
        linhas += [f"| {n} | {h['ambiente']} | {h['kernel_instalado'] or '—'} | {h['kernel_exigido']} |" for n, h in kern]
        linhas += ["", "A simulação compara o **exigido** com o que o repositório do servidor oferece; "
                       "se o repositório não tiver a versão, o resumo da Fase 2 avisa."]

    if plano["fora_inventario"]:
        linhas += ["", "## Servidores no Qualys fora do inventário Ansible", ""]
        linhas += [f"- {k}: {v} vulnerabilidades" for k, v in plano["fora_inventario"].items()]
    if plano.get("fora_inventario_conhecidos"):
        linhas += ["", "**Fora do inventário, já explicados** (`fora_inventario_conhecidos` no policy.yml):", ""]
        linhas += [f"- {k}: {v} vulnerabilidades" for k, v in plano["fora_inventario_conhecidos"].items()]
    linhas += ["", "Detalhe por pacote: artefato **plano** → `plano.csv`."]
    return "\n".join(linhas) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description="Gera o plano de patch a partir das detecções")
    ap.add_argument("--entrada", default="out/deteccoes.json")
    ap.add_argument("--policy", default="policy/policy.yml")
    ap.add_argument("--inventario", default="inventories/hosts.yml")
    ap.add_argument("--inventario-windows", default="inventories/windows.yml")
    ap.add_argument("--saida", default="out")
    args = ap.parse_args()

    with open(args.entrada, encoding="utf-8") as f:
        deteccoes = json.load(f)["deteccoes"]
    politica = q.carregar_yaml(args.policy)
    mapa_inv = q.mapa_inventario(q.carregar_yaml(args.inventario))
    mapa_win = q.mapa_windows(q.carregar_yaml(args.inventario_windows)) if os.path.exists(args.inventario_windows) else {}

    plano = gerar(deteccoes, politica, mapa_inv, mapa_win)
    os.makedirs(args.saida, exist_ok=True)

    with open(os.path.join(args.saida, "plano.json"), "w", encoding="utf-8") as f:
        json.dump({k: v for k, v in plano.items() if k != "linhas"}, f, ensure_ascii=False, indent=1)

    colunas = ["host", "ambiente", "ip", "qid", "severidade", "categoria", "titulo", "pacote",
               "versao_instalada", "versao_exigida", "rota", "motivo"]
    with open(os.path.join(args.saida, "plano.csv"), "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=colunas)
        w.writeheader()
        w.writerows(sorted(plano["linhas"], key=lambda l: (l["host"], ORDEM[l["rota"]], l["pacote"])))

    md = resumo_markdown(plano)
    with open(os.path.join(args.saida, "resumo.md"), "w", encoding="utf-8") as f:
        f.write(md)

    print(md)
    return 0


if __name__ == "__main__":
    sys.exit(main())
