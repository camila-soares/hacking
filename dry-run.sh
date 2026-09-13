#!/usr/bin/env bash
#
# dry-run.sh — sobe o ambiente de ENSAIO da simulação anti-phishing no seu lab.
#
# O que faz:
#   - sobe o Mailpit (coletor de e-mail local — nada sai da máquina)
#   - confere se o binário do GoPhish está por perto
#   - imprime as URLs e o passo a passo do dashboard
#
# O que NÃO faz: não envia e-mail, não cria campanha, não captura nada.
# A campanha você monta na interface do GoPhish (ver 04-dry-run-lab.md).
#
# Uso:
#   ./dry-run.sh          # sobe o Mailpit e mostra as URLs
#   ./dry-run.sh --down   # derruba o Mailpit
#
set -euo pipefail

GRN=$'\e[32m'; BLU=$'\e[34m'; YEL=$'\e[33m'; RED=$'\e[31m'; RST=$'\e[0m'
ok(){   echo "${GRN}[ok]${RST} $*"; }
info(){ echo "${BLU}[..]${RST} $*"; }
warn(){ echo "${YEL}[!!]${RST} $*"; }

if [[ "${1:-}" == "--down" ]]; then
  docker rm -f mailpit >/dev/null 2>&1 && ok "Mailpit derrubado." || warn "Mailpit não estava rodando."
  exit 0
fi

# Docker presente?
if ! command -v docker >/dev/null 2>&1; then
  echo "${RED}[xx]${RST} Docker não encontrado. Instale o Docker antes de rodar o ensaio."
  exit 1
fi

# Sobe (ou reaproveita) o Mailpit
if docker ps --format '{{.Names}}' | grep -q '^mailpit$'; then
  ok "Mailpit já está rodando."
else
  info "Subindo o Mailpit (SMTP local + interface web)..."
  docker run -d --name mailpit -p 1025:1025 -p 8025:8025 axllent/mailpit >/dev/null
  ok "Mailpit no ar."
fi

# GoPhish por perto?
if [[ -x "./gophish" ]]; then
  ok "Binário do GoPhish encontrado nesta pasta."
else
  warn "GoPhish não está aqui. Baixe em https://github.com/gophish/gophish/releases e rode ./gophish"
fi

cat <<TXT

${BLU}== Ambiente de ensaio pronto ==${RST}

  Caixa de entrada falsa (Mailpit):  ${GRN}http://localhost:8025${RST}
  SMTP local (Sending Profile):      ${GRN}localhost:1025${RST}   (sem usuário/senha)
  Painel do GoPhish:                 ${GRN}https://127.0.0.1:3333${RST}

Passos no GoPhish (detalhe em 04-dry-run-lab.md):
  1. Sending Profile -> Host: localhost:1025 | From: rh@teste.local -> Send Test Email
  2. Landing Page -> Capture Passwords DESLIGADO | Redirect: sua educativo.html
  3. Email Template -> cole o texto com {{.URL}} e {{.Tracker}} (Add Tracking Image)
  4. Group -> uma linha: você
  5. Campaign -> URL http://127.0.0.1:8080 -> Launch
  6. Veja o e-mail em http://localhost:8025, clique no link e acompanhe o dashboard

Ao terminar:  ./dry-run.sh --down
TXT
