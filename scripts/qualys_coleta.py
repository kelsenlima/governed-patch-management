#!/usr/bin/env python3
"""
Fase 1 — Coleta.

Busca no Qualys as detecções abertas de severidade 4/5 dos servidores (por tag),
classifica cada QID pela KnowledgeBase e grava out/deteccoes.json.

Uso:
    QUALYS_USER=... QUALYS_PASS=... python3 scripts/qualys_coleta.py \
        --policy policy/policy.yml --saida out/deteccoes.json

Variáveis de ambiente:
    QUALYS_USER, QUALYS_PASS   credenciais da API (variable group "qualys-api")
    QUALYS_API_URL             padrão: https://qualysapi.qg2.apps.qualys.com
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import asdict
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import qualys_lib as q  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description="Coleta de detecções do Qualys")
    ap.add_argument("--policy", default="policy/policy.yml")
    ap.add_argument("--saida", default="out/deteccoes.json")
    ap.add_argument("--csv-local", help="(teste) usa um CSV local em vez da API")
    ap.add_argument("--kb-local", help="(teste) usa um XML local da KnowledgeBase")
    args = ap.parse_args()

    politica = q.carregar_yaml(args.policy)
    api = os.environ.get("QUALYS_API_URL", "https://qualysapi.qg2.apps.qualys.com").rstrip("/")
    usuario = os.environ.get("QUALYS_USER", "").strip()
    senha = os.environ.get("QUALYS_PASS", "").strip()

    if args.csv_local:
        with open(args.csv_local, encoding="utf-8") as f:
            csv_texto = f.read()
    else:
        if not usuario or not senha:
            print("##vso[task.logissue type=error]QUALYS_USER/QUALYS_PASS vazios (variable group qualys-api).")
            return 1
        tags = list(politica["tags_qualys"]) + list(politica.get("tags_qualys_windows", []))
        print(f"Consultando Qualys ({api}) — tags {tags} — severidades {politica['severidades']}")
        csv_texto = q.buscar_deteccoes(api, usuario, senha, tags, str(politica["severidades"]))

    deteccoes = q.parse_deteccoes_csv(csv_texto)
    qids = sorted({d.qid for d in deteccoes})
    print(f"Detecções abertas: {len(deteccoes)} | QIDs distintos: {len(qids)}")

    if args.kb_local:
        with open(args.kb_local, encoding="utf-8") as f:
            kb = q.parse_kb(f.read())
    else:
        kb = q.buscar_categorias(api, usuario, senha, qids)

    excluidas = {c.lower() for c in politica.get("categorias_excluidas", [])}
    dentro, fora = [], 0
    for d in deteccoes:
        info = kb.get(d.qid, {})
        d.categoria = info.get("categoria", "Desconhecida")
        d.titulo = info.get("titulo", "")
        if d.categoria.lower() in excluidas:
            fora += 1
            continue
        dentro.append(d)

    print(f"Fora do escopo (categorias {sorted(excluidas)}): {fora} | No escopo: {len(dentro)}")

    os.makedirs(os.path.dirname(args.saida) or ".", exist_ok=True)
    with open(args.saida, "w", encoding="utf-8") as f:
        json.dump(
            {
                "gerado_em": datetime.now(timezone.utc).isoformat(),
                "total_no_escopo": len(dentro),
                "deteccoes": [asdict(d) for d in dentro],
            },
            f,
            ensure_ascii=False,
            indent=1,
        )
    print(f"Gravado: {args.saida}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except q.QualysErro as e:
        print(f"##vso[task.logissue type=error]{e}")
        sys.exit(1)
