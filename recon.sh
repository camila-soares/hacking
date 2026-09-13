#!/bin/bash
# ============================================================
#  recon.sh — automação de recon para bug bounty
#  Uso: ./recon.sh alvo.com [--rapido]
#  Autor: gerado com Claude
#
#  ATENÇÃO: use APENAS em alvos que você tem autorização
#  escrita para testar (escopo do programa de bug bounty).
# ============================================================

set -euo pipefail

# ── cores ────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# ── argumentos ───────────────────────────────────────────────
if [[ $# -lt 1 ]]; then
    echo -e "${RED}Uso: $0 <dominio> [--rapido]${NC}"
    echo "  --rapido   pula nuclei e waybackurls (ideal pra testes iniciais)"
    exit 1
fi

ALVO="${1}"
MODO_RAPIDO=false
[[ "${2:-}" == "--rapido" ]] && MODO_RAPIDO=true

# ── diretório de saída ────────────────────────────────────────
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTPUT_DIR="recon_${ALVO}_${TIMESTAMP}"
mkdir -p "${OUTPUT_DIR}"/{subdominios,hosts,nuclei,params,relatorio}

LOG="${OUTPUT_DIR}/recon.log"
exec > >(tee -a "${LOG}") 2>&1

# ── funções utilitárias ───────────────────────────────────────
banner() {
    echo -e "\n${CYAN}${BOLD}══════════════════════════════════════════${NC}"
    echo -e "${CYAN}${BOLD}  $1${NC}"
    echo -e "${CYAN}${BOLD}══════════════════════════════════════════${NC}\n"
}

ok()   { echo -e "${GREEN}[✔]${NC} $1"; }
info() { echo -e "${YELLOW}[→]${NC} $1"; }
erro() { echo -e "${RED}[✘]${NC} $1"; }

checar_ferramenta() {
    if ! command -v "$1" &>/dev/null; then
        erro "Ferramenta não encontrada: $1"
        echo "    Instale com: go install $2@latest"
        return 1
    fi
    ok "$1 encontrado"
}

# ── verificação de dependências ───────────────────────────────
banner "Verificando dependências"

DEPS_OK=true
checar_ferramenta subfinder  "github.com/projectdiscovery/subfinder/v2/cmd/subfinder"  || DEPS_OK=false
checar_ferramenta httpx      "github.com/projectdiscovery/httpx/cmd/httpx"              || DEPS_OK=false
checar_ferramenta gau        "github.com/lc/gau/v2/cmd/gau"                             || DEPS_OK=false
checar_ferramenta waybackurls "github.com/tomnomnom/waybackurls"                        || DEPS_OK=false
checar_ferramenta ffuf       "github.com/ffuf/ffuf/v2"                                  || DEPS_OK=false

if ! $MODO_RAPIDO; then
    checar_ferramenta nuclei "github.com/projectdiscovery/nuclei/v3/cmd/nuclei"         || DEPS_OK=false
fi

if ! $DEPS_OK; then
    erro "Instale as ferramentas faltantes e rode novamente."
    exit 1
fi

# ── início ────────────────────────────────────────────────────
banner "Recon: ${ALVO}"
info "Modo rápido: ${MODO_RAPIDO}"
info "Saída em: ${OUTPUT_DIR}/"
echo ""

# ─────────────────────────────────────────────────────────────
# PASSO 1 — Descoberta de subdomínios
# ─────────────────────────────────────────────────────────────
banner "PASSO 1/4 — Descoberta de subdomínios"

SUBS_RAW="${OUTPUT_DIR}/subdominios/raw.txt"

info "Rodando subfinder..."
subfinder -d "${ALVO}" \
    -silent \
    -o "${SUBS_RAW}" \
    -timeout 30 \
    2>/dev/null || true

# adiciona o próprio domínio raiz
echo "${ALVO}" >> "${SUBS_RAW}"

TOTAL_SUBS=$(sort -u "${SUBS_RAW}" | wc -l | tr -d ' ')
sort -u "${SUBS_RAW}" -o "${SUBS_RAW}"

ok "Subdomínios encontrados: ${TOTAL_SUBS}"

# ─────────────────────────────────────────────────────────────
# PASSO 2 — Filtrar hosts ativos com httpx
# ─────────────────────────────────────────────────────────────
banner "PASSO 2/4 — Filtrando hosts ativos"

HOSTS_ATIVOS="${OUTPUT_DIR}/hosts/ativos.txt"
HOSTS_JSON="${OUTPUT_DIR}/hosts/detalhes.json"

info "Rodando httpx (isso pode demorar alguns minutos)..."
httpx \
    -l "${SUBS_RAW}" \
    -silent \
    -status-code \
    -title \
    -tech-detect \
    -follow-redirects \
    -timeout 10 \
    -retries 2 \
    -threads 50 \
    -json -o "${HOSTS_JSON}" \
    -o "${HOSTS_ATIVOS}" \
    2>/dev/null || true

TOTAL_ATIVOS=$(wc -l < "${HOSTS_ATIVOS}" | tr -d ' ')
ok "Hosts ativos: ${TOTAL_ATIVOS} de ${TOTAL_SUBS} subdomínios"

# extrair URLs com status 200 e 403 (candidatos a IDOR)
grep -E '\[200\]|\[403\]' "${HOSTS_ATIVOS}" > \
    "${OUTPUT_DIR}/hosts/interessantes.txt" 2>/dev/null || true

ok "Hosts com 200/403 (candidatos a testar): $(wc -l < "${OUTPUT_DIR}/hosts/interessantes.txt" | tr -d ' ')"

# ─────────────────────────────────────────────────────────────
# PASSO 3 — Coleta de parâmetros históricos
# ─────────────────────────────────────────────────────────────
banner "PASSO 3/4 — Coletando parâmetros históricos"

PARAMS_DIR="${OUTPUT_DIR}/params"

info "Rodando waybackurls..."
waybackurls "${ALVO}" 2>/dev/null \
    | sort -u \
    > "${PARAMS_DIR}/wayback.txt" || true

info "Rodando gau..."
gau "${ALVO}" \
    --threads 5 \
    --retries 3 \
    2>/dev/null \
    | sort -u \
    > "${PARAMS_DIR}/gau.txt" || true

# consolidar e filtrar URLs com parâmetros
cat "${PARAMS_DIR}/wayback.txt" "${PARAMS_DIR}/gau.txt" \
    | sort -u \
    > "${PARAMS_DIR}/todas.txt"

# URLs com parâmetros (foco de injeção / IDOR)
grep "=" "${PARAMS_DIR}/todas.txt" \
    | sort -u \
    > "${PARAMS_DIR}/com_parametros.txt" || true

# extensões de alto risco: backup, config, logs
grep -iE "\.(bak|sql|log|env|config|conf|xml|json|yaml|yml|gz|zip)$" \
    "${PARAMS_DIR}/todas.txt" \
    > "${PARAMS_DIR}/arquivos_sensiveis.txt" 2>/dev/null || true

TOTAL_URLS=$(wc -l < "${PARAMS_DIR}/todas.txt" | tr -d ' ')
TOTAL_PARAMS=$(wc -l < "${PARAMS_DIR}/com_parametros.txt" | tr -d ' ')
TOTAL_SENSIVEIS=$(wc -l < "${PARAMS_DIR}/arquivos_sensiveis.txt" | tr -d ' ')

ok "URLs coletadas: ${TOTAL_URLS}"
ok "URLs com parâmetros: ${TOTAL_PARAMS}"
ok "Arquivos sensíveis encontrados: ${TOTAL_SENSIVEIS}"

# ─────────────────────────────────────────────────────────────
# PASSO 4 — Nuclei (scan de misconfigurações)
# ─────────────────────────────────────────────────────────────
banner "PASSO 4/4 — Nuclei (scan automático)"

NUCLEI_DIR="${OUTPUT_DIR}/nuclei"

if $MODO_RAPIDO; then
    info "Modo rápido ativo — nuclei pulado."
    info "Rode manualmente depois: nuclei -l ${HOSTS_ATIVOS} -severity medium,high,critical"
else
    info "Atualizando templates do nuclei..."
    nuclei -update-templates -silent 2>/dev/null || true

    info "Rodando nuclei (pode demorar bastante dependendo do alvo)..."
    nuclei \
        -l "${HOSTS_ATIVOS}" \
        -severity medium,high,critical \
        -tags "exposure,misconfig,cve,xss,sqli,ssrf,idor,auth,lfi" \
        -silent \
        -json \
        -o "${NUCLEI_DIR}/findings.json" \
        -o "${NUCLEI_DIR}/findings.txt" \
        -timeout 10 \
        -retries 2 \
        -rate-limit 50 \
        2>/dev/null || true

    TOTAL_FINDINGS=0
    if [[ -f "${NUCLEI_DIR}/findings.txt" ]]; then
        TOTAL_FINDINGS=$(wc -l < "${NUCLEI_DIR}/findings.txt" | tr -d ' ')
    fi

    ok "Findings nuclei: ${TOTAL_FINDINGS}"
fi

# ─────────────────────────────────────────────────────────────
# RELATÓRIO FINAL
# ─────────────────────────────────────────────────────────────
banner "Relatório Final"

RELATORIO="${OUTPUT_DIR}/relatorio/resumo.md"

cat > "${RELATORIO}" << MARKDOWN
# Relatório de Recon — ${ALVO}
**Data:** $(date "+%d/%m/%Y %H:%M")
**Modo rápido:** ${MODO_RAPIDO}

---

## Resumo executivo

| Métrica | Valor |
|---|---|
| Subdomínios descobertos | ${TOTAL_SUBS} |
| Hosts ativos (httpx) | ${TOTAL_ATIVOS} |
| URLs históricas coletadas | ${TOTAL_URLS} |
| URLs com parâmetros | ${TOTAL_PARAMS} |
| Arquivos sensíveis | ${TOTAL_SENSIVEIS} |
| Findings nuclei | $([ "$MODO_RAPIDO" = true ] && echo "pulado" || echo "${TOTAL_FINDINGS}") |

---

## Próximos passos (manual — Burp Suite)

- [ ] Inspecionar hosts com status 403 (possível bypass de acesso)
- [ ] Testar URLs com parâmetros numéricos (IDOR — trocar o ID)
- [ ] Verificar arquivos sensíveis encontrados
- [ ] Testar verbos HTTP alternativos (PUT, PATCH, DELETE) nos endpoints
- [ ] Checar headers de segurança ausentes (CSP, HSTS, X-Frame-Options)
- [ ] Buscar endpoints de admin/dashboard não linkados

## Arquivos gerados

\`\`\`
${OUTPUT_DIR}/
├── subdominios/raw.txt             # todos os subdomínios
├── hosts/ativos.txt                # hosts vivos com status
├── hosts/interessantes.txt         # 200/403 (foco de teste)
├── params/com_parametros.txt       # URLs com ?param= (foco de injeção/IDOR)
├── params/arquivos_sensiveis.txt   # backups, configs, logs expostos
├── nuclei/findings.txt             # vulnerabilidades automáticas
└── relatorio/resumo.md             # este arquivo
\`\`\`

---

## Avisos legais

> Teste realizado com autorização no escopo do programa de bug bounty.
> Invasão sem autorização é crime (art. 154-A do Código Penal brasileiro).
MARKDOWN

echo ""
echo -e "${BOLD}Alvo:${NC}              ${ALVO}"
echo -e "${BOLD}Subdomínios:${NC}       ${TOTAL_SUBS}"
echo -e "${BOLD}Hosts ativos:${NC}      ${TOTAL_ATIVOS}"
echo -e "${BOLD}URLs c/ parâmetros:${NC} ${TOTAL_PARAMS}"
echo -e "${BOLD}Arquivos sensíveis:${NC} ${TOTAL_SENSIVEIS}"
echo ""
echo -e "${GREEN}${BOLD}Recon concluído!${NC}"
echo -e "Relatório em: ${CYAN}${RELATORIO}${NC}"
echo -e "Logs em:      ${CYAN}${LOG}${NC}"
echo ""
echo -e "${YELLOW}Próximo passo: abra o Burp e carregue:${NC}"
echo -e "  ${OUTPUT_DIR}/params/com_parametros.txt"
echo -e "  ${OUTPUT_DIR}/hosts/interessantes.txt"
