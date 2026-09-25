#!/usr/bin/env bash
# ============================================================
#  Bug Bounty Toolkit — extrai o projeto do zip e organiza
#  os arquivos de deploy, pronto pra rodar no VPS.
#
#  Uso (a partir da raiz do repo "hacking"):
#    ./deploy/extract-and-prepare.sh
#
#  Depois:
#    cd bb-toolkit && ./deploy.sh
# ============================================================
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ZIP_FILE="$REPO_ROOT/bb-toolkit 2.zip"
TARGET_DIR="$REPO_ROOT/bb-toolkit"

log()  { printf '\033[1;32m[extract]\033[0m %s\n' "$1"; }
die()  { printf '\033[1;31m[extract]\033[0m %s\n' "$1" >&2; exit 1; }

command -v unzip >/dev/null || die "unzip não encontrado. Instale com: sudo apt install unzip"
[ -f "$ZIP_FILE" ] || die "Não encontrei '$ZIP_FILE'. Rode este script a partir do repo hacking."

if [ -d "$TARGET_DIR" ]; then
  die "'$TARGET_DIR' já existe. Remova ou renomeie antes de extrair de novo."
fi

log "Extraindo bb-toolkit 2.zip..."
unzip -q "$ZIP_FILE" -d "$REPO_ROOT"

# remove lixo de macOS e caches que não servem pra nada no servidor
log "Limpando arquivos irrelevantes (__MACOSX, .DS_Store, __pycache__)..."
rm -rf "$REPO_ROOT/__MACOSX"
find "$TARGET_DIR" -name '.DS_Store' -delete
rm -rf "$TARGET_DIR/__pycache__"

log "Copiando scripts de deploy pra dentro de bb-toolkit/..."
cp "$REPO_ROOT/deploy/deploy.sh" "$TARGET_DIR/deploy.sh"
cp "$REPO_ROOT/deploy/Caddyfile" "$TARGET_DIR/Caddyfile"
cp "$REPO_ROOT/deploy/.env.example" "$TARGET_DIR/.env.example"
chmod +x "$TARGET_DIR/deploy.sh"

log "Pronto. Próximos passos:"
echo "  cd bb-toolkit"
echo "  ./deploy.sh"
