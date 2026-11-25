#!/usr/bin/env bash
# =============================================================================
# diagnostico_host.sh — checagem rápida de um servidor ANTES do patch (somente leitura)
#
# Uso (no servidor, como root):
#   bash diagnostico_host.sh
#
# Cobre os problemas mais comuns encontrados nos primeiros testes:
#   - kernel novo instalado e não carregado (falta reboot ou GRUB fixado)
#   - repositório de terceiros com chave GPG vencida (ex.: InfluxData)
#   - repositório de outra versão do SO no sources.list (ex.: focal num 24.04)
#   - serviços que JÁ estavam com falha (para não confundir com o patch)
#   - sysctl com chave inválida
#   - espaço em /boot e quantidade de kernels instalados
# Não altera pacotes nem configuração (só atualiza o índice do apt, como um "apt update").
# =============================================================================
set -u

ok()    { printf '  \033[32m[OK]\033[0m    %s\n' "$*"; }
aviso() { printf '  \033[33m[AVISO]\033[0m %s\n' "$*"; AVISOS=$((AVISOS + 1)); }
info()  { printf '  [info]  %s\n' "$*"; }
titulo(){ printf '\n== %s ==\n' "$*"; }
AVISOS=0

titulo "Sistema"
. /etc/os-release 2>/dev/null
info "SO: ${PRETTY_NAME:-desconhecido} (codename: ${VERSION_CODENAME:-?})"
info "Host: $(hostname)  ·  uptime: $(uptime -p 2>/dev/null)"

# ----------------------------------------------------------------- kernel/GRUB
titulo "Kernel e GRUB"
EM_USO=$(uname -r)
NOVO=$(ls -1 /boot/vmlinuz-* 2>/dev/null | grep -v rescue | sed 's#^/boot/vmlinuz-##' | sort -V | tail -n 1)
QTD=$(ls -1 /boot/vmlinuz-* 2>/dev/null | grep -vc rescue)
info "Kernel em uso: ${EM_USO}"
info "Kernel mais novo instalado: ${NOVO:-?}  (${QTD} kernels em /boot)"
if [ -n "$NOVO" ] && [ "$EM_USO" != "$NOVO" ]; then
  aviso "Kernel ${NOVO} instalado e NÃO carregado (falta reboot ou GRUB fixado)."
else
  ok "Rodando o kernel mais novo instalado."
fi
if [ -f /var/run/reboot-required ]; then
  aviso "Reboot pendente: $(tr '\n' ' ' < /var/run/reboot-required.pkgs 2>/dev/null)"
fi
if command -v grubby >/dev/null 2>&1; then
  info "GRUB (grubby): $(grubby --default-kernel 2>/dev/null)"
else
  G=$(grep -E '^GRUB_DEFAULT=' /etc/default/grub 2>/dev/null | tail -n 1 | cut -d= -f2- | tr -d '"')
  info "GRUB_DEFAULT=${G:-0}"
  [ "$G" = "saved" ] && info "grub-editenv: $(grub-editenv list 2>/dev/null | tr '\n' ' ')"
  FIX=$(echo "$G $(grub-editenv list 2>/dev/null)" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+-[0-9]+[^ >"]*' | tail -n 1)
  if [ -n "$FIX" ] && [ "$FIX" != "$NOVO" ]; then
    aviso "GRUB fixado no kernel ${FIX} (mais novo: ${NOVO}). O reboot NÃO troca o kernel — ver README 'Corrigir GRUB fixado'."
  elif [ -n "$G" ] && [ "$G" != "0" ] && [ "$G" != "saved" ] && [ -z "$FIX" ]; then
    aviso "GRUB_DEFAULT=${G} fora do padrão: conferir qual kernel o boot carrega."
  else
    ok "GRUB inicia no kernel padrão."
  fi
fi
BOOT_LIVRE=$(df -Pm /boot | awk 'NR == 2 { print $4 }')
if [ "${BOOT_LIVRE:-0}" -lt 150 ]; then aviso "/boot com só ${BOOT_LIVRE} MB livres (mínimo 150)."; else ok "/boot com ${BOOT_LIVRE} MB livres."; fi
[ "${QTD:-0}" -gt 3 ] && info "Muitos kernels antigos: depois de validar o mais novo, 'apt autoremove --purge' / 'dnf remove --oldinstallonly'."

# ----------------------------------------------------------------- repositórios
titulo "Repositórios"
if command -v apt-get >/dev/null 2>&1; then
  if [ -n "${VERSION_CODENAME:-}" ]; then
    OUTROS=$(grep -rhE '^deb ' /etc/apt/sources.list /etc/apt/sources.list.d/*.list 2>/dev/null \
             | grep -E 'ubuntu|debian' | grep -v "$VERSION_CODENAME" | grep -v -E 'influxdata|zabbix|docker' || true)
    if [ -n "$OUTROS" ]; then
      aviso "Repositório de outra versão do SO (o host é ${VERSION_CODENAME}):"
      echo "$OUTROS" | sed 's/^/            /'
    else
      ok "Nenhum repositório de outra versão do SO."
    fi
  fi
  SAIDA=$(apt-get update -q 2>&1)
  ERROS=$(echo "$SAIDA" | grep -E '^(E:|W: ?GPG error|Err:|W: ?Failed to fetch)' || true)
  if [ -n "$ERROS" ]; then
    aviso "apt update com erro:"
    echo "$ERROS" | sed 's/^/            /' | cut -c1-220
    echo "$ERROS" | grep -q 'NO_PUBKEY' && info "NO_PUBKEY = chave do fornecedor trocada/vencida (InfluxData: ver README)."
  else
    ok "apt update sem erro."
  fi
  ls /etc/apt/sources.list.d/ 2>/dev/null | grep -vE '\.(list|sources)$' | sed 's/^/  [info]  arquivo ignorado pelo apt: /'
elif command -v dnf >/dev/null 2>&1; then
  if dnf -q makecache >/dev/null 2>&1; then ok "dnf makecache sem erro."; else aviso "dnf makecache com erro (rodar 'dnf makecache' para ver)."; fi
fi

# ----------------------------------------------------------------- serviços
titulo "Serviços"
FALHOS=$(systemctl list-units --type=service --state=failed --no-legend --plain 2>/dev/null | awk '{ print $1 }')
if [ -n "$FALHOS" ]; then
  aviso "Serviços JÁ com falha (anotar: não são causados pelo patch):"
  for s in $FALHOS; do echo "            $s  (enabled: $(systemctl is-enabled "$s" 2>/dev/null))"; done
else
  ok "Nenhum serviço com falha."
fi
info "Portas 80/443: $(ss -ltnp 2>/dev/null | awk '$4 ~ /:(80|443)$/ { print $4, $6 }' | tr '\n' ' ')"

# ----------------------------------------------------------------- sysctl
titulo "sysctl"
# (não roda "sysctl --system": isso APLICARIA valores; só lê o estado do serviço de boot)
if systemctl is-failed --quiet systemd-sysctl 2>/dev/null; then
  aviso "systemd-sysctl falhou no boot (chave inválida em /etc/sysctl.conf ou /etc/sysctl.d). Detalhe:"
  echo "            SYSTEMD_LOG_LEVEL=debug /usr/lib/systemd/systemd-sysctl 2>&1 | grep -iE \"fail|invalid|couldn't\""
else
  ok "systemd-sysctl sem falha."
fi

titulo "Resultado"
if [ "$AVISOS" -eq 0 ]; then
  printf '  \033[32mPronto para o patch.\033[0m\n'
else
  printf '  \033[33m%d aviso(s): resolver ou anotar antes do patch.\033[0m\n' "$AVISOS"
fi
exit 0
