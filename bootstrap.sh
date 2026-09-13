#!/usr/bin/env bash
#
# hacking-lab :: bootstrap
# Prepara uma VM Kali (Apple Silicon / ARM64) como estacao de estudo de
# seguranca ofensiva, dentro de uma rede ISOLADA.
#
# Uso:
#   sudo ./bootstrap.sh          # instala o toolkit + roda os diagnosticos
#        ./bootstrap.sh --check  # so roda os diagnosticos (adaptador + isolamento)
#        ./bootstrap.sh --help
#
# REGRA DO LAB: so rode ataques contra maquinas SUAS ou com autorizacao
# escrita (rules of engagement). O lab existe pra voce nunca precisar de um
# alvo real pra aprender.
#
set -euo pipefail

# ---------- estetica ----------
RED=$'\e[31m'; GRN=$'\e[32m'; YEL=$'\e[33m'; BLU=$'\e[34m'; RST=$'\e[0m'
ok()   { echo "${GRN}[ok]${RST}  $*"; }
info() { echo "${BLU}[..]${RST}  $*"; }
warn() { echo "${YEL}[!!]${RST}  $*"; }
err()  { echo "${RED}[xx]${RST}  $*" >&2; }
step() { echo; echo "${BLU}== $* ==${RST}"; }

# ---------- contexto ----------
LAB_USER="${SUDO_USER:-$USER}"
LAB_HOME="$(eval echo "~${LAB_USER}")"
LAB_DIR="${LAB_HOME}/lab"
TOOLS_DIR="${LAB_HOME}/tools"

# Ferramentas das Aulas 2 e 3. A maioria ja vem no Kali "default";
# reinstalar e barato e cobre o caso de uma imagem enxuta (kali-light).
PKGS=(metasploit-framework wifite aircrack-ng hostapd dnsmasq php git macchanger iw net-tools curl)

usage() {
  sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'
  exit 0
}

need_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    err "Rode com sudo:  sudo ./bootstrap.sh"
    exit 1
  fi
}

check_arch() {
  step "Arquitetura"
  local arch; arch="$(uname -m)"
  info "Detectado: ${arch}"
  if [[ "${arch}" == "aarch64" || "${arch}" == "arm64" ]]; then
    ok "Kali ARM64 (nativo no M1)."
    warn "Payloads .exe do modulo Meterpreter sao x86/x64: na VM Windows ARM"
    warn "eles rodam sob emulacao. E esperado. Pra estudar o fluxo, resolve."
  else
    warn "Arquitetura ${arch} (nao-ARM). Ajuste as expectativas do modulo Windows."
  fi
}

install_tools() {
  step "Instalando o toolkit"
  export DEBIAN_FRONTEND=noninteractive
  info "apt update..."
  apt-get update -qq
  info "Instalando: ${PKGS[*]}"
  apt-get install -y "${PKGS[@]}"
  ok "Toolkit instalado."
}

clone_eviltrust() {
  step "EvilTrust"
  local dest="${TOOLS_DIR}/evilTrust"
  if [[ -d "${dest}/.git" ]]; then
    ok "Ja clonado em ${dest} (pulando)."
    return
  fi
  sudo -u "${LAB_USER}" mkdir -p "${TOOLS_DIR}"
  info "Clonando repositorio..."
  sudo -u "${LAB_USER}" git clone --depth 1 https://github.com/s4vitar/evilTrust.git "${dest}"
  [[ -f "${dest}/evilTrust.sh" ]] && chmod +x "${dest}/evilTrust.sh" || true
  ok "EvilTrust em ${dest}"
  warn "So suba o AP falso contra o SEU proprio SSID + seu proprio dispositivo."
}

setup_dirs() {
  step "Estrutura de trabalho"
  for d in payloads handshakes loot logs reports; do
    sudo -u "${LAB_USER}" mkdir -p "${LAB_DIR}/${d}"
  done
  ok "Criado em ${LAB_DIR}/ {payloads,handshakes,loot,logs,reports}"
  info "loot/handshakes/payloads/logs estao no .gitignore — nunca vao pro Git."
}

check_wifi() {
  step "Diagnostico: adaptador Wi-Fi"
  local ifaces
  ifaces="$(iw dev 2>/dev/null | awk '$1=="Interface"{print $2}')"
  if [[ -z "${ifaces}" ]]; then
    warn "Nenhuma interface wireless encontrada."
    warn "No M1 o Wi-Fi interno NAO passa pra VM. Voce precisa de um adaptador"
    warn "USB (chipset RTL8812AU ou AR9271) + passthrough de USB pra esta VM."
    return
  fi
  for i in ${ifaces}; do ok "Interface: ${i}"; done
  if iw list 2>/dev/null | grep -A12 "Supported interface modes" | grep -qiw monitor; then
    ok "Modo monitor: SUPORTADO."
    info "Pra ativar depois:  sudo airmon-ng start <iface>"
  else
    warn "Modo monitor nao detectado neste adaptador — Wifite/EvilTrust nao vao funcionar."
  fi
}

check_isolation() {
  step "Diagnostico: isolamento de rede"
  info "Durante a instalacao o NAT costuma estar ligado (pra baixar pacotes)."
  info "Depois de configurar, mude a VM pra HOST-ONLY e rode:  ./bootstrap.sh --check"
  echo
  if curl -s -m 4 -o /dev/null https://example.com; then
    warn "Internet ALCANCAVEL a partir da Kali."
    warn "OK durante o setup. Em modo de ataque, isso deveria FALHAR (rede isolada)."
  else
    ok "Sem internet a partir da Kali — coerente com rede isolada."
  fi
  local gw; gw="$(ip route 2>/dev/null | awk '/default/{print $3; exit}')"
  [[ -n "${gw}" ]] && info "Gateway atual: ${gw}" || info "Sem gateway default (bem isolado)."
}

snapshot_note() {
  step "Proximo passo manual"
  info "No Fusion/UTM: tire um SNAPSHOT desta VM limpa agora."
  info "E o que transforma 'quebrei tudo' em 'restaura em 10s'."
}

main() {
  case "${1:-}" in
    -h|--help) usage ;;
    --check)
      check_arch; check_wifi; check_isolation
      exit 0 ;;
  esac
  need_root
  check_arch
  install_tools
  clone_eviltrust
  setup_dirs
  check_wifi
  check_isolation
  snapshot_note
  echo
  ok "Lab pronto. Bom estudo — e sempre dentro do escopo."
}

main "$@"
