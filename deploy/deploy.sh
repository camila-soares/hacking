#!/usr/bin/env bash
# ============================================================
#  Bug Bounty Toolkit — deploy em VPS (Ubuntu 22.04/24.04)
#
#  Automatiza: firewall, Docker, .env com API_TOKEN, build/up,
#  healthcheck e systemd (docker no boot).
#
#  Uso:
#    cd bb-toolkit/           # diretório com docker-compose.yml e Dockerfile
#    ../deploy/deploy.sh      # (ou copie este script pra dentro do projeto)
#
#  Requer: usuário com sudo, Ubuntu/Debian. Idempotente — pode
#  rodar de novo sem quebrar nada já configurado.
# ============================================================
set -euo pipefail

COMPOSE_DIR="$(pwd)"
HEALTH_URL="http://localhost:8080/api/health"
HEALTH_TIMEOUT=180

log()  { printf '\033[1;32m[deploy]\033[0m %s\n' "$1"; }
warn() { printf '\033[1;33m[deploy]\033[0m %s\n' "$1"; }
die()  { printf '\033[1;31m[deploy]\033[0m %s\n' "$1" >&2; exit 1; }

[ -f "$COMPOSE_DIR/docker-compose.yml" ] || die "docker-compose.yml não encontrado em $COMPOSE_DIR. Rode este script de dentro do diretório do bb-toolkit."
[ "$(id -u)" -ne 0 ] || die "Não rode como root — use um usuário com sudo."
command -v sudo >/dev/null || die "sudo não encontrado."

# ── 1. Firewall ────────────────────────────────────────────
if ! command -v ufw >/dev/null; then
  log "Instalando ufw..."
  sudo apt-get update -qq && sudo apt-get install -y ufw
fi
if ! sudo ufw status | grep -q "Status: active"; then
  log "Configurando firewall (libera apenas SSH e HTTPS)..."
  sudo ufw default deny incoming
  sudo ufw default allow outgoing
  sudo ufw allow OpenSSH
  sudo ufw allow 443/tcp
  sudo ufw --force enable
else
  log "ufw já está ativo — pulando configuração de firewall."
fi

# ── 2. Docker ───────────────────────────────────────────────
if ! command -v docker >/dev/null; then
  log "Instalando Docker Engine..."
  curl -fsSL https://get.docker.com | sudo sh
  sudo usermod -aG docker "$USER"
  warn "Usuário adicionado ao grupo docker. Rode 'newgrp docker' ou reabra a sessão SSH antes de continuar."
  exit 0
else
  log "Docker já instalado ($(docker --version))."
fi
command -v docker compose >/dev/null 2>&1 || sudo docker compose version >/dev/null 2>&1 || die "Docker Compose plugin não encontrado."

sudo systemctl enable docker >/dev/null 2>&1 || true

# ── 3. .env com API_TOKEN ────────────────────────────────────
if [ ! -f "$COMPOSE_DIR/.env" ]; then
  log "Gerando API_TOKEN e criando .env..."
  TOKEN="$(openssl rand -hex 32)"
  printf 'API_TOKEN=%s\n' "$TOKEN" > "$COMPOSE_DIR/.env"
  chmod 600 "$COMPOSE_DIR/.env"
  warn "Token gerado — guarde-o: $TOKEN"
else
  log ".env já existe — mantendo API_TOKEN atual."
fi

# ── 4. Build & up ─────────────────────────────────────────────
log "Subindo containers (docker compose up --build -d)..."
docker compose up --build -d

# ── 5. Healthcheck ────────────────────────────────────────────
log "Aguardando healthcheck em $HEALTH_URL (até ${HEALTH_TIMEOUT}s)..."
elapsed=0
until curl -fs "$HEALTH_URL" >/dev/null 2>&1; do
  sleep 5
  elapsed=$((elapsed + 5))
  if [ "$elapsed" -ge "$HEALTH_TIMEOUT" ]; then
    warn "Healthcheck não respondeu a tempo. Verifique os logs: docker compose logs -f toolkit"
    exit 1
  fi
done

log "Toolkit no ar e saudável."
log "Próximo passo: configure o reverse proxy (veja deploy/Caddyfile) para expor via HTTPS em vez da porta 8080 direto."
