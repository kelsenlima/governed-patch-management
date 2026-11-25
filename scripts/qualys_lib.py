"""
Biblioteca comum da esteira ansible-patch-qualys.

- Acesso à API do Qualys VMDR (Host Detection em CSV + KnowledgeBase)
- Parser de CSV do Qualys e do campo "Results" (pacote / versão instalada / exigida)
- Leitura do inventário Ansible (YAML) e da política de patch

Usa só a biblioteca padrão do Python + PyYAML (instalado junto com o ansible-core).
"""

from __future__ import annotations

import base64
import csv
import io
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field

ABERTOS = ("New", "Active", "Re-Opened")


# --------------------------------------------------------------------------- #
# API do Qualys
# --------------------------------------------------------------------------- #
class QualysErro(RuntimeError):
    """Erro de comunicação ou resposta inesperada da API do Qualys."""


def _post(url: str, usuario: str, senha: str, campos: dict, timeout: int = 600,
          tentativas: int = 3, espera_base: int = 20) -> str:
    token = base64.b64encode(f"{usuario}:{senha}".encode("utf-8")).decode("ascii")
    dados = urllib.parse.urlencode(campos).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=dados,
        method="POST",
        headers={
            "Authorization": f"Basic {token}",
            "X-Requested-With": "ansible-patch-qualys",
            "Content-Type": "application/x-www-form-urlencoded",
        },
    )
    # Falha de rede (DNS, conexão, timeout) é tentada de novo; erro HTTP (401, 409...) não.
    ultimo: Exception | None = None
    for tentativa in range(1, tentativas + 1):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as e:  # type: ignore[attr-defined]
            corpo = e.read().decode("utf-8", errors="replace")[:800]
            raise QualysErro(f"HTTP {e.code} em {url}: {corpo}") from e
        except (urllib.error.URLError, TimeoutError, ConnectionError) as e:  # type: ignore[attr-defined]
            ultimo = e
            if tentativa < tentativas:
                espera = espera_base * tentativa
                print(f"Falha de rede ({getattr(e, 'reason', e)}); nova tentativa {tentativa + 1}/{tentativas} em {espera}s",
                      file=sys.stderr)
                time.sleep(espera)
    raise QualysErro(f"Falha de rede em {url} após {tentativas} tentativas: {getattr(ultimo, 'reason', ultimo)}") from ultimo


def buscar_deteccoes(api_base: str, usuario: str, senha: str, tags: list[str], severidades: str) -> str:
    """Detecções abertas (New/Active/Re-Opened) dos hosts com as tags informadas, em CSV,
    incluindo o campo Results (pacote/versão)."""
    texto = _post(
        f"{api_base}/api/4.0/fo/asset/host/vm/detection/",
        usuario,
        senha,
        {
            "action": "list",
            "show_igs": "0",
            "severities": severidades,
            "status": ",".join(ABERTOS),
            "show_results": "1",
            "use_tags": "1",
            "tag_set_by": "name",
            "tag_include_selector": "any",
            "tag_set_include": ",".join(tags),
            "truncation_limit": "0",
            "output_format": "CSV_NO_METADATA",
        },
    )
    if texto.lstrip().startswith("<"):
        raise QualysErro("Qualys retornou XML em vez de CSV: " + texto.strip()[:800])
    return texto


def buscar_categorias(api_base: str, usuario: str, senha: str, qids: list[str]) -> dict[str, dict]:
    """Categoria e título de cada QID (KnowledgeBase)."""
    if not qids:
        return {}
    xml = _post(
        f"{api_base}/api/2.0/fo/knowledge_base/vuln/",
        usuario,
        senha,
        {"action": "list", "details": "Basic", "ids": ",".join(qids)},
    )
    if "KNOWLEDGE_BASE_VULN_LIST_OUTPUT" not in xml:
        raise QualysErro("Resposta inesperada da KnowledgeBase: " + xml[:800])
    return parse_kb(xml)


def parse_kb(xml: str) -> dict[str, dict]:
    def tag(bloco: str, nome: str) -> str:
        m = re.search(rf"<{nome}>([\s\S]*?)</{nome}>", bloco)
        if not m:
            return ""
        v = m.group(1).strip()
        v = re.sub(r"^<!\[CDATA\[", "", v)
        v = re.sub(r"\]\]>$", "", v)
        return v.strip()

    kb: dict[str, dict] = {}
    for m in re.finditer(r"<VULN>([\s\S]*?)</VULN>", xml):
        bloco = m.group(1)
        kb[tag(bloco, "QID")] = {"categoria": tag(bloco, "CATEGORY"), "titulo": tag(bloco, "TITLE")}
    return kb


# --------------------------------------------------------------------------- #
# Parsers
# --------------------------------------------------------------------------- #
@dataclass
class Pacote:
    nome: str
    instalada: str = ""
    exigida: str = ""


@dataclass
class Deteccao:
    host_id: str
    ip: str
    dns: str
    netbios: str
    so: str
    qid: str
    severidade: int
    status: str
    first_found: str
    resultado: str
    categoria: str = ""
    titulo: str = ""
    pacotes: list[Pacote] = field(default_factory=list)

    @property
    def nome(self) -> str:
        if self.dns:
            return self.dns.split(".")[0].lower()
        return (self.netbios or self.ip).lower()

    @property
    def windows(self) -> bool:
        return "windows" in self.so.lower()


def parse_deteccoes_csv(texto: str) -> list[Deteccao]:
    """Converte o CSV_NO_METADATA da Host Detection API em objetos Deteccao."""
    texto = texto.strip()
    if not texto:
        return []
    leitor = csv.DictReader(io.StringIO(texto))
    obrig = ["Host ID", "IP Address", "Operating System", "DNS Name", "Netbios Name", "QID",
             "Status", "Severity", "First Found Datetime", "Results"]
    faltando = [c for c in obrig if c not in (leitor.fieldnames or [])]
    if faltando:
        raise QualysErro(f"Colunas ausentes no CSV do Qualys: {faltando}. Colunas: {leitor.fieldnames}")

    saida: list[Deteccao] = []
    for l in leitor:
        if l["Status"] not in ABERTOS:
            continue
        d = Deteccao(
            host_id=l["Host ID"],
            ip=l["IP Address"],
            dns=l["DNS Name"] or "",
            netbios=l["Netbios Name"] or "",
            so=l["Operating System"] or "",
            qid=l["QID"],
            severidade=int(l["Severity"] or 0),
            status=l["Status"],
            first_found=l["First Found Datetime"] or "",
            resultado=l["Results"] or "",
        )
        d.pacotes = parse_resultado(d.resultado)
        saida.append(d)
    return saida


_CABECALHO = re.compile(r"^\s*package\s+installed\s+version\s+required\s+version\s*$", re.I)


def parse_resultado(texto: str) -> list[Pacote]:
    """Extrai a tabela 'Package / Installed Version / Required Version' do campo Results.

    Exemplo (Ubuntu):
        Package\tInstalled Version\tRequired Version
        linux\t6.8.0-1066-gcp\t6.8.0-1073
    """
    pacotes: list[Pacote] = []
    if not texto:
        return pacotes
    linhas = [l for l in re.split(r"[\r\n]+", texto) if l.strip()]
    dentro = False
    for linha in linhas:
        normal = re.sub(r"\s+", " ", linha.replace("\t", " ")).strip()
        if _CABECALHO.match(normal):
            dentro = True
            continue
        if not dentro:
            continue
        partes = normal.split(" ")
        if len(partes) < 2 or not re.match(r"^[a-z0-9][a-z0-9.+_:\-]*$", partes[0], re.I):
            # fim da tabela (texto livre depois dela)
            dentro = False
            continue
        nome = partes[0]
        instalada = partes[1] if len(partes) >= 3 else ""
        exigida = partes[-1]
        if not any(p.nome == nome for p in pacotes):
            pacotes.append(Pacote(nome=nome, instalada=instalada, exigida=exigida))
    return pacotes


# --------------------------------------------------------------------------- #
# Inventário e política
# --------------------------------------------------------------------------- #
def carregar_yaml(caminho: str):
    import yaml  # PyYAML vem com o ansible-core

    with open(caminho, encoding="utf-8") as f:
        return yaml.safe_load(f)


def mapa_inventario(inventario: dict) -> dict[str, dict]:
    """Retorna {ip: {"host": nome, "ambiente": grupo}} a partir de inventories/hosts.yml.

    Espera grupos 'producao' e 'nao_producao' (filhos de 'linux')."""
    mapa: dict[str, dict] = {}

    def varrer(grupo: dict | None, nome_grupo: str, ambiente: str | None):
        if not isinstance(grupo, dict):
            return
        amb = nome_grupo if nome_grupo in ("producao", "nao_producao") else ambiente
        for host, hv in (grupo.get("hosts") or {}).items():
            ip = (hv or {}).get("ansible_host", host)
            mapa[str(ip)] = {"host": host, "ambiente": amb or "desconhecido"}
        for filho, gv in (grupo.get("children") or {}).items():
            varrer(gv, filho, amb)

    for nome, grupo in (inventario or {}).items():
        varrer(grupo, nome, None)
    return mapa


def casa_padrao(nome: str, padroes: list[str]) -> bool:
    """Compara nome de pacote com padrões estilo glob simples (ex.: 'php*')."""
    for p in padroes or []:
        regex = "^" + re.escape(p).replace(r"\*", ".*") + "$"
        if re.match(regex, nome, re.I):
            return True
    return False


# --------------------------------------------------------------------------- #
# Windows (W1 — somente plano)
# --------------------------------------------------------------------------- #
_RE_KB = re.compile(r"\bKB\s?(\d{6,8})\b", re.I)
_RE_CONFIG = re.compile(
    r"(SMB|TLS|SSL|cipher|certificate|certificado|signing|assinatura|registry|registro|"
    r"configura|disabled|enabled|policy|pol[ií]tica|weak|fraco|null session|LLMNR|NetBIOS|"
    r"RDP .*(encryption|NLA)|anonymous|an[oô]nimo|password|senha)", re.I)
# configuração inequívoca (vence mesmo com "Microsoft Windows" no título, se não houver KB)
_RE_CONFIG_FORTE = re.compile(
    r"(SMB Signing|SMBv1|SSL|TLS|Certificate|Cipher|NULL Session|LLMNR|NetBIOS Name|Weak|Anonymous|"
    r"Password Policy|Account Lockout|Insecure .*Protocol|Hash Disclosure)", re.I)
_RE_MS_APP = re.compile(
    r"(Office|Microsoft 365|Outlook|Excel|Word\b|PowerPoint|Teams|OneDrive|Edge|SQL Server|Exchange|"
    r"SharePoint|Visual C\+\+|Visual Studio|\.NET Core|ASP\.NET Core|\.NET \d|PowerShell \d|Power BI|"
    r"Windows Terminal|Skype)", re.I)
_RE_WIN_UPDATE = re.compile(
    r"(Microsoft Windows|Windows Server|Cumulative Update|Servicing Stack|Security Update|"
    r"\.NET Framework|Microsoft \.NET\b|Internet Explorer|Win32k|Hyper-V|Remote Desktop|Kerberos|NTLM|"
    r"LSASS|Print Spooler|Windows Kernel|Patch Tuesday)", re.I)

CLASSES_WINDOWS = {
    "WINDOWS_UPDATE": "KB do Windows (Windows Update)",
    "MICROSOFT_APP": "Produto Microsoft fora do Windows Update (Office, Edge, SQL, .NET Core...)",
    "TERCEIROS": "Software de terceiro (Chrome, Java, 7-Zip...)",
    "CONFIG": "Configuração (TLS, SMB, certificado, política) — não é patch",
}


def classificar_windows(titulo: str, categoria: str, resultado: str) -> dict:
    """Classifica uma detecção Windows para o plano W1.

    Retorna {"classe", "kbs", "reboot_pendente", "evidencia"}."""
    t = titulo or ""
    r = resultado or ""
    kbs = sorted({f"KB{m}" for m in _RE_KB.findall(t + "\n" + r)})
    cat = (categoria or "").lower()

    if not kbs and _RE_CONFIG_FORTE.search(t):
        classe = "CONFIG"
    elif _RE_MS_APP.search(t):
        classe = "MICROSOFT_APP"
    elif _RE_WIN_UPDATE.search(t) or (cat == "windows" and "microsoft" in t.lower()) or kbs:
        classe = "WINDOWS_UPDATE"
    elif cat in ("security policy", "general remote services", "tcp/ip", "information gathering",
                 "firewall") or _RE_CONFIG.search(t):
        classe = "CONFIG"
    elif "microsoft" in t.lower():
        classe = "MICROSOFT_APP"
    else:
        classe = "TERCEIROS"

    evid = " ".join(r.split())[:180]
    return {
        "classe": classe,
        "kbs": kbs,
        "reboot_pendente": bool(re.search(r"reboot|reinicializa", r, re.I)),
        "evidencia": evid,
    }


def mapa_windows(inventario: dict) -> dict[str, dict]:
    """{nome_curto_minúsculo: {"host": nome, "ambiente": grupo}} a partir de inventories/windows.yml."""
    mapa: dict[str, dict] = {}

    def varrer(grupo, nome_grupo, ambiente):
        if not isinstance(grupo, dict):
            return
        amb = nome_grupo if nome_grupo in ("producao", "nao_producao") else ambiente
        for host, hv in (grupo.get("hosts") or {}).items():
            if amb:
                mapa[host.lower()] = {"host": host, "ambiente": amb}
                fqdn = str((hv or {}).get("ansible_host", "")).lower()
                if fqdn:
                    mapa[fqdn.split(".")[0]] = {"host": host, "ambiente": amb}
        for filho, gv in (grupo.get("children") or {}).items():
            varrer(gv, filho, amb)

    for nome, grupo in (inventario or {}).items():
        varrer(grupo, nome, None)
    return mapa

