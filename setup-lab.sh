#!/bin/bash
# ============================================================
#  setup-lab.sh — Laboratório de AppSec dentro da VM (Kali/Ubuntu ARM)
#
#  Instala Podman ou Docker, sobe alvos vulneráveis (WebGoat, Juice Shop,
#  DVWA) em portas organizadas e checa a postura de rede da VM.
#
#  Uso:
#    bash setup-lab.sh            # instala + sobe os alvos + checa rede
#    bash setup-lab.sh --check    # só a checagem de isolamento de rede
#    bash setup-lab.sh --down     # derruba os alvos
#    bash setup-lab.sh --podman   # força uso do Podman (pula Docker)
#    bash setup-lab.sh --docker   # força uso do Docker (pula Podman)
#
#  ATENÇÃO: alvos propositalmente vulneráveis. Use SOMENTE numa VM em
#  rede Host-Only. Nunca exponha estes containers em rede real.
# ============================================================

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
banner(){ echo -e "\n${CYAN}${BOLD}══════  $1  ══════${NC}\n"; }
ok(){ echo -e "${GREEN}[✔]${NC} $1"; }
info(){ echo -e "${YELLOW}[→]${NC} $1"; }
erro(){ echo -e "${RED}[✘]${NC} $1"; }
warn(){ echo -e "${YELLOW}[!]${NC} $1"; }

COMPOSE_FILE="docker-compose.lab.yml"
SUDO=""; [[ "$(id -u)" -ne 0 ]] && SUDO="sudo"

# ── porta-alvo (não colide com o toolkit em 8080) ─────────────
P_JUICE=3000
P_WEBGOAT=8081
P_WEBWOLF=9090
P_DVWA=8082

# ─────────────────────────────────────────────────────────────
#  Detectar runtime: Podman ou Docker
#  Prioridade: flag CLI > Podman (se disponível) > Docker
# ─────────────────────────────────────────────────────────────
FORCE_RUNTIME=""
RUNTIME=""        # "podman" ou "docker"
COMPOSE_CMD=""    # comando compose final

for arg in "$@"; do
  case "$arg" in
    --podman) FORCE_RUNTIME="podman" ;;
    --docker) FORCE_RUNTIME="docker" ;;
  esac
done

detectar_runtime() {
  if [[ "$FORCE_RUNTIME" == "podman" ]]; then
    if command -v podman &>/dev/null; then
      RUNTIME="podman"
    else
      erro "Podman não encontrado. Instale com: sudo apt install podman"
      exit 1
    fi
  elif [[ "$FORCE_RUNTIME" == "docker" ]]; then
    if command -v docker &>/dev/null; then
      RUNTIME="docker"
    else
      erro "Docker não encontrado."
      exit 1
    fi
  elif command -v podman &>/dev/null; then
    RUNTIME="podman"
  elif command -v docker &>/dev/null; then
    RUNTIME="docker"
  fi

  # Detectar compose
  if [[ "$RUNTIME" == "podman" ]]; then
    if podman compose version &>/dev/null 2>&1; then
      COMPOSE_CMD="podman compose"
    elif command -v podman-compose &>/dev/null; then
      COMPOSE_CMD="podman-compose"
    else
      COMPOSE_CMD=""
    fi
  elif [[ "$RUNTIME" == "docker" ]]; then
    if docker compose version &>/dev/null 2>&1; then
      COMPOSE_CMD="docker compose"
    elif command -v docker-compose &>/dev/null; then
      COMPOSE_CMD="docker-compose"
    else
      COMPOSE_CMD=""
    fi
  fi
}

# ─────────────────────────────────────────────────────────────
#  Checagem de rede (o passo de segurança que define um "lab")
# ─────────────────────────────────────────────────────────────
checar_rede() {
    banner "Postura de rede da VM"

    info "Interfaces e IPs desta VM:"
    ip -4 -o addr show 2>/dev/null | awk '{print "     "$2" → "$4}' \
        | grep -v "127.0.0.1" || echo "     (nenhuma)"

    echo ""
    info "Testando se a VM alcança a internet..."
    if curl -s --max-time 4 -o /dev/null https://1.1.1.1 2>/dev/null; then
        warn "A VM TEM acesso à internet AGORA."
        warn "Isso é esperado durante a instalação (para baixar as imagens)."
        echo -e "     ${BOLD}Depois do setup, troque a rede da VM para Host-Only${NC}"
        echo -e "     no UTM (Network → Host Only) e rode: bash setup-lab.sh --check"
        echo -e "     Alvo vulnerável não pode ficar acessível fora da VM."
    else
        ok "Sem acesso à internet — postura de laboratório isolado correta."
    fi

    echo ""
    info "Onde os alvos estão escutando (se já subiram):"
    ($SUDO $RUNTIME ps --format '     {{.Names}} → {{.Ports}}' 2>/dev/null \
        | grep -E 'webgoat|juice|dvwa') || echo "     (alvos ainda não iniciados)"
}

# ─────────────────────────────────────────────────────────────
#  --down
# ─────────────────────────────────────────────────────────────
if [[ "${1:-}" == "--down" ]]; then
    detectar_runtime
    banner "Derrubando os alvos"
    if [[ -n "$COMPOSE_CMD" ]]; then
        $SUDO $COMPOSE_CMD -f "$COMPOSE_FILE" down 2>/dev/null || true
    else
        warn "Compose não encontrado — parando containers individualmente."
        $SUDO $RUNTIME stop lab-juiceshop lab-webgoat lab-dvwa 2>/dev/null || true
        $SUDO $RUNTIME rm lab-juiceshop lab-webgoat lab-dvwa 2>/dev/null || true
    fi
    ok "Alvos parados."
    exit 0
fi

# ─────────────────────────────────────────────────────────────
#  --check
# ─────────────────────────────────────────────────────────────
if [[ "${1:-}" == "--check" ]]; then
    detectar_runtime
    checar_rede
    exit 0
fi

# ─────────────────────────────────────────────────────────────
#  Instalação do runtime (Podman ou Docker)
# ─────────────────────────────────────────────────────────────
detectar_runtime

if [[ -z "$RUNTIME" ]]; then
    banner "Instalando container runtime"

    # Tenta Podman primeiro (mais leve, rootless, ótimo em Kali/Debian)
    if [[ "$FORCE_RUNTIME" != "docker" ]]; then
        info "Tentando instalar Podman (recomendado para Kali/Debian)..."
        if $SUDO apt-get update -qq && $SUDO apt-get install -y podman 2>/dev/null; then
            RUNTIME="podman"
            ok "Podman instalado: $(podman --version)"
        fi
    fi

    # Fallback para Docker
    if [[ -z "$RUNTIME" ]]; then
        info "Instalando Docker (script oficial)..."
        curl -fsSL https://get.docker.com | $SUDO sh
        $SUDO usermod -aG docker "$USER" 2>/dev/null || true
        RUNTIME="docker"
        ok "Docker instalado. (Talvez precise relogar para usar sem sudo.)"
    fi

    detectar_runtime  # re-detecta compose
else
    banner "Container Runtime"
    ok "$RUNTIME já instalado: $($RUNTIME --version 2>&1 | head -1)"
fi

# Instalar compose se necessário
if [[ -z "$COMPOSE_CMD" ]]; then
    info "Instalando compose..."
    if [[ "$RUNTIME" == "podman" ]]; then
        if pip3 install podman-compose 2>/dev/null || $SUDO apt-get install -y podman-compose 2>/dev/null; then
            COMPOSE_CMD="podman-compose"
            ok "podman-compose instalado."
        else
            warn "Não foi possível instalar podman-compose."
            warn "Instale manualmente: pip3 install podman-compose"
        fi
    else
        $SUDO apt-get update -qq && $SUDO apt-get install -y docker-compose-plugin 2>/dev/null || \
            warn "Instale o docker compose plugin manualmente se o up falhar."
        detectar_runtime
    fi
fi

ARCH=$(uname -m)
info "Arquitetura: ${ARCH} (Apple Silicon usa arm64 nativo)"
info "Runtime: ${BOLD}${RUNTIME}${NC} | Compose: ${BOLD}${COMPOSE_CMD:-'(não instalado)'}${NC}"

# ─────────────────────────────────────────────────────────────
#  Gera o compose dos alvos
# ─────────────────────────────────────────────────────────────
banner "Definindo os alvos"

cat > "$COMPOSE_FILE" <<YAML
name: appsec-lab
services:
  juice-shop:
    image: bkimminich/juice-shop:latest
    container_name: lab-juiceshop
    ports: ["${P_JUICE}:3000"]
    restart: unless-stopped
    networks: [lab-net]

  webgoat:
    image: webgoat/webgoat:latest
    container_name: lab-webgoat
    ports: ["${P_WEBGOAT}:8080", "${P_WEBWOLF}:9090"]
    restart: unless-stopped
    networks: [lab-net]

  dvwa:
    image: sagikazarmark/dvwa:latest
    container_name: lab-dvwa
    platform: linux/amd64      # emulado no M1 — leve para web
    ports: ["${P_DVWA}:80"]
    restart: unless-stopped
    networks: [lab-net]

networks:
  lab-net:
    driver: bridge
YAML
ok "Gerado: ${COMPOSE_FILE}"

# ─────────────────────────────────────────────────────────────
#  Sobe os alvos
# ─────────────────────────────────────────────────────────────
banner "Subindo os alvos (o primeiro pull pode demorar)"

if [[ -n "$COMPOSE_CMD" ]]; then
    $SUDO $COMPOSE_CMD -f "$COMPOSE_FILE" up -d
else
    erro "Nenhum compose disponível. Subindo containers manualmente..."
    $SUDO $RUNTIME run -d --name lab-juiceshop --network lab-net \
        -p ${P_JUICE}:3000 --restart unless-stopped bkimminich/juice-shop:latest
    $SUDO $RUNTIME run -d --name lab-webgoat --network lab-net \
        -p ${P_WEBGOAT}:8080 -p ${P_WEBWOLF}:9090 --restart unless-stopped webgoat/webgoat:latest
    $SUDO $RUNTIME run -d --name lab-dvwa --network lab-net \
        -p ${P_DVWA}:80 --restart unless-stopped sagikazarmark/dvwa:latest
fi

info "Aguardando os serviços ficarem de pé..."
sleep 8
for nome in lab-juiceshop lab-webgoat lab-dvwa; do
    if $SUDO $RUNTIME ps --format '{{.Names}}' | grep -q "$nome"; then
        ok "$nome no ar"
    else
        warn "$nome não subiu — veja: $RUNTIME logs $nome"
    fi
done

# ─────────────────────────────────────────────────────────────
#  Checagem de rede + resumo
# ─────────────────────────────────────────────────────────────
checar_rede

banner "Laboratório pronto"
VM_IP=$(ip -4 -o addr show 2>/dev/null | awk '{print $4}' | grep -v '^127' | cut -d/ -f1 | head -1)
echo -e "  Runtime: ${BOLD}${RUNTIME}${NC}"
echo -e "  Acesse pelos endereços (dentro da VM use localhost):"
echo -e "    Juice Shop (Angular)  → ${CYAN}http://localhost:${P_JUICE}${NC}"
echo -e "    WebGoat (Spring Boot) → ${CYAN}http://localhost:${P_WEBGOAT}/WebGoat${NC}"
echo -e "    WebWolf               → ${CYAN}http://localhost:${P_WEBWOLF}/WebWolf${NC}"
echo -e "    DVWA                  → ${CYAN}http://localhost:${P_DVWA}${NC}"
[[ -n "${VM_IP:-}" ]] && echo -e "  (IP da VM p/ apontar seu toolkit: ${BOLD}${VM_IP}${NC})"
echo ""
echo -e "${YELLOW}${BOLD}Comandos úteis (${RUNTIME}):${NC}"
echo -e "  Listar containers: ${CYAN}$RUNTIME ps${NC}"
echo -e "  Parar alvos:       ${CYAN}bash setup-lab.sh --down${NC}"
echo -e "  Ver logs:          ${CYAN}$RUNTIME logs -f lab-juiceshop${NC}"
echo ""
echo -e "${YELLOW}${BOLD}Próximos passos:${NC}"
echo -e "  1. UTM → Network → ${BOLD}Host Only${NC}, depois: bash setup-lab.sh --check"
echo -e "  2. Tire um ${BOLD}snapshot${NC} da VM limpa no UTM antes de explorar."
echo -e "  3. Aponte seu recon toolkit para os alvos acima."
echo ""
echo -e "${RED}Só rode ferramentas de ataque contra estes alvos locais ou escopo autorizado.${NC}"
