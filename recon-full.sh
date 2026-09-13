#!/bin/bash
# ============================================================
#  recon-full.sh — recon + fuzzing + classificação de params
#  Uso:
#    ./recon-full.sh alvo.com               (recon completo)
#    ./recon-full.sh alvo.com --rapido      (sem nuclei)
#    ./recon-full.sh --classify output_dir  (só classificar)
#    ./recon-full.sh --fuzz output_dir      (só fuzzing)
#
#  ATENÇÃO: use APENAS em alvos com autorização escrita.
#  Invasão sem autorização é crime — art. 154-A CP.
# ============================================================

set -euo pipefail

# ── cores ────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# ── helpers ───────────────────────────────────────────────────
banner()  { echo -e "\n${CYAN}${BOLD}══════  $1  ══════${NC}\n"; }
ok()      { echo -e "${GREEN}[✔]${NC} $1"; }
info()    { echo -e "${YELLOW}[→]${NC} $1"; }
erro()    { echo -e "${RED}[✘]${NC} $1"; }
destaque(){ echo -e "${BOLD}$1${NC}"; }

checar_ferramenta() {
    command -v "$1" &>/dev/null && ok "$1 ok" || {
        erro "$1 não encontrado — instale: go install $2@latest"
        return 1
    }
}

# ── argumentos ───────────────────────────────────────────────
if [[ $# -lt 1 ]]; then
    echo -e "${RED}Uso: $0 <dominio> [--rapido]${NC}"
    echo -e "     $0 --classify <pasta_de_saida>"
    echo -e "     $0 --fuzz     <pasta_de_saida>"
    exit 1
fi

# modos especiais
if [[ "${1}" == "--classify" ]]; then
    MODO=classify
    OUTPUT_DIR="${2}"
elif [[ "${1}" == "--fuzz" ]]; then
    MODO=fuzz
    OUTPUT_DIR="${2}"
else
    MODO=full
    ALVO="${1}"
    MODO_RAPIDO=false
    [[ "${2:-}" == "--rapido" ]] && MODO_RAPIDO=true
    TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    OUTPUT_DIR="recon_${ALVO}_${TIMESTAMP}"
fi

# ── criação de diretórios ─────────────────────────────────────
mkdir -p "${OUTPUT_DIR}"/{subdominios,hosts,nuclei,params,fuzzing,classificacao,relatorio}
LOG="${OUTPUT_DIR}/recon.log"
exec > >(tee -a "${LOG}") 2>&1

# ═════════════════════════════════════════════════════════════
#  FASE 5 — Fuzzing de endpoints com ffuf
# ═════════════════════════════════════════════════════════════
fase_fuzzing() {
    banner "FASE 5 — Fuzzing de endpoints (ffuf)"

    local HOSTS_ATIVOS="${OUTPUT_DIR}/hosts/ativos.txt"
    local FUZZ_DIR="${OUTPUT_DIR}/fuzzing"

    if [[ ! -f "${HOSTS_ATIVOS}" ]]; then
        erro "Arquivo de hosts ativos não encontrado: ${HOSTS_ATIVOS}"
        return 1
    fi

    # wordlists (ajusta o caminho se necessário)
    local WL_COMMON="${HOME}/SecLists/Discovery/Web-Content/raft-medium-words.txt"
    local WL_API="${HOME}/SecLists/Discovery/Web-Content/api/api-endpoints.txt"
    local WL_BACKUP="${HOME}/SecLists/Discovery/Web-Content/raft-medium-extensions.txt"
    local WL_PARAMS="${HOME}/SecLists/Discovery/Web-Content/burp-parameter-names.txt"

    # fallback leve se SecLists não estiver instalado
    if [[ ! -f "${WL_COMMON}" ]]; then
        info "SecLists não encontrado — usando wordlist embutida reduzida"
        cat > /tmp/wl_fallback.txt << 'WORDLIST'
admin
api
v1
v2
v3
login
logout
register
user
users
account
accounts
profile
dashboard
settings
config
backup
export
import
upload
download
files
documents
report
reports
internal
test
debug
health
status
metrics
swagger
openapi
graphql
.env
.git
.htaccess
web.config
WORDLIST
        WL_COMMON="/tmp/wl_fallback.txt"
        WL_API="${WL_COMMON}"
    fi

    local TOTAL_HOSTS
    TOTAL_HOSTS=$(wc -l < "${HOSTS_ATIVOS}" | tr -d ' ')
    local COUNT=0

    while IFS= read -r HOST_LINHA; do
        # extrai só a URL base (remove [status] [título] etc.)
        local HOST
        HOST=$(echo "${HOST_LINHA}" | awk '{print $1}')
        [[ -z "${HOST}" ]] && continue

        COUNT=$((COUNT + 1))
        local HOST_SLUG
        HOST_SLUG=$(echo "${HOST}" | sed 's|https\?://||;s|/.*||;s|[^a-zA-Z0-9_.-]|_|g')

        info "[${COUNT}/${TOTAL_HOSTS}] Fuzzing: ${HOST}"

        # ── 5a. Descoberta de diretórios/endpoints ──────────────
        ffuf \
            -w "${WL_COMMON}" \
            -u "${HOST}/FUZZ" \
            -mc 200,201,204,301,302,403,405 \
            -ac \
            -silent \
            -timeout 5 \
            -rate 100 \
            -json \
            -o "${FUZZ_DIR}/${HOST_SLUG}_dirs.json" \
            2>/dev/null || true

        # parsear resultado JSON → txt legível
        if [[ -f "${FUZZ_DIR}/${HOST_SLUG}_dirs.json" ]]; then
            python3 -c "
import json, sys
try:
    data = json.load(open('${FUZZ_DIR}/${HOST_SLUG}_dirs.json'))
    results = data.get('results', [])
    for r in results:
        print(f\"{r['status']}  {r['length']:>8}b  {r['url']}\")
except: pass
" > "${FUZZ_DIR}/${HOST_SLUG}_dirs.txt" 2>/dev/null || true
        fi

        # ── 5b. Fuzzing de endpoints de API ─────────────────────
        if [[ -f "${WL_API}" ]]; then
            ffuf \
                -w "${WL_API}" \
                -u "${HOST}/api/FUZZ" \
                -mc 200,201,204,401,403 \
                -ac \
                -silent \
                -timeout 5 \
                -rate 80 \
                -json \
                -o "${FUZZ_DIR}/${HOST_SLUG}_api.json" \
                2>/dev/null || true
        fi

        # ── 5c. Fuzzing de parâmetros em endpoints encontrados ──
        if [[ -f "${FUZZ_DIR}/${HOST_SLUG}_dirs.txt" && -f "${WL_PARAMS}" ]]; then
            # pegar primeiros 10 endpoints 200 para fuzzing de parâmetros
            grep "^200" "${FUZZ_DIR}/${HOST_SLUG}_dirs.txt" \
                | awk '{print $3}' \
                | head -10 \
                | while IFS= read -r ENDPOINT; do
                    local EP_SLUG
                    EP_SLUG=$(echo "${ENDPOINT}" | sed 's|[^a-zA-Z0-9]|_|g' | tail -c 40)
                    ffuf \
                        -w "${WL_PARAMS}" \
                        -u "${ENDPOINT}?FUZZ=1" \
                        -mc 200 \
                        -fs 0 \
                        -ac \
                        -silent \
                        -timeout 5 \
                        -rate 60 \
                        -o "${FUZZ_DIR}/${HOST_SLUG}_params_${EP_SLUG}.json" \
                        2>/dev/null || true
                done
        fi

    done < "${HOSTS_ATIVOS}"

    # consolidar todos os achados de fuzzing
    local FUZZ_CONSOLIDADO="${FUZZ_DIR}/todos_endpoints.txt"
    find "${FUZZ_DIR}" -name "*_dirs.txt" -exec cat {} \; 2>/dev/null \
        | sort -u \
        > "${FUZZ_CONSOLIDADO}" || true

    local TOTAL_ENDPOINTS
    TOTAL_ENDPOINTS=$(wc -l < "${FUZZ_CONSOLIDADO}" | tr -d ' ')
    ok "Endpoints descobertos pelo fuzzing: ${TOTAL_ENDPOINTS}"
    ok "Resultados em: ${FUZZ_DIR}/"
}

# ═════════════════════════════════════════════════════════════
#  FASE 6 — Classificação de parâmetros por vulnerabilidade
# ═════════════════════════════════════════════════════════════
fase_classificacao() {
    banner "FASE 6 — Classificação de parâmetros"

    local PARAMS_FILE="${OUTPUT_DIR}/params/com_parametros.txt"
    local CLASS_DIR="${OUTPUT_DIR}/classificacao"

    if [[ ! -f "${PARAMS_FILE}" ]]; then
        erro "Arquivo de parâmetros não encontrado: ${PARAMS_FILE}"
        return 1
    fi

    python3 << PYTHON
import re
from urllib.parse import urlparse, parse_qs
from collections import defaultdict
from pathlib import Path

PARAMS_FILE = "${PARAMS_FILE}"
CLASS_DIR   = Path("${CLASS_DIR}")

# ── mapeamento de padrões → tipo de vulnerabilidade ──────────
PADROES = {
    "IDOR": [
        r"\bid\b", r"user[_-]?id", r"account[_-]?id", r"order[_-]?id",
        r"record[_-]?id", r"doc[_-]?id", r"contract[_-]?id", r"item[_-]?id",
        r"\bnum\b", r"\bnumber\b", r"\bno\b", r"codigo", r"code",
        r"uuid", r"guid", r"ref", r"identifier"
    ],
    "SSRF": [
        r"\burl\b", r"\buri\b", r"\blink\b", r"endpoint", r"proxy",
        r"\bhost\b", r"\bdomain\b", r"callback", r"webhook", r"fetch",
        r"\bload\b", r"resource", r"service", r"remote", r"src",
        r"path", r"dest", r"destination"
    ],
    "Open Redirect": [
        r"redirect", r"return", r"\bnext\b", r"\bgoto\b", r"target",
        r"continue", r"\bback\b", r"forward", r"location", r"returnto",
        r"returnurl", r"exit", r"out", r"ref", r"referrer"
    ],
    "LFI / RFI": [
        r"\bfile\b", r"\bpath\b", r"\bdir\b", r"folder", r"include",
        r"require", r"template", r"\bpage\b", r"\bdoc\b", r"document",
        r"read", r"view", r"show", r"fetch", r"load", r"content"
    ],
    "XSS": [
        r"\bq\b", r"query", r"search", r"keyword", r"input",
        r"\btext\b", r"message", r"comment", r"title", r"\bname\b",
        r"description", r"body", r"content", r"value", r"data",
        r"output", r"html", r"msg"
    ],
    "SQL Injection": [
        r"\bsort\b", r"order", r"orderby", r"order_by", r"column",
        r"category", r"filter", r"\bwhere\b", r"\bfield\b", r"table",
        r"limit", r"offset", r"page", r"\bfrom\b", r"\bselect\b",
        r"group", r"having"
    ],
    "Command Injection": [
        r"\bcmd\b", r"command", r"\bexec\b", r"execute", r"\brun\b",
        r"process", r"\bshell\b", r"system", r"ping", r"trace",
        r"dig", r"host", r"lookup"
    ],
    "Mass Assignment": [
        r"\brole\b", r"\badmin\b", r"status", r"access", r"permission",
        r"level", r"\bgroup\b", r"privilege", r"scope", r"rights",
        r"activated", r"verified", r"is_admin", r"is_staff"
    ],
    "JWT / Auth": [
        r"token", r"jwt", r"\bauth\b", r"authorization", r"bearer",
        r"session", r"api_key", r"apikey", r"secret", r"password",
        r"passwd", r"credential"
    ],
}

def classificar_url(url):
    try:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        resultados = []
        for param_name in params:
            p = param_name.lower()
            for vuln, patterns in PADROES.items():
                for pattern in patterns:
                    if re.search(pattern, p, re.IGNORECASE):
                        resultados.append({
                            "vuln": vuln,
                            "param": param_name,
                            "valor": params[param_name][0],
                            "url": url,
                        })
                        break  # evita duplicar mesma vuln pra mesmo param
        return resultados
    except Exception:
        return []

# processar arquivo
por_vuln = defaultdict(list)
total_urls = 0

with open(PARAMS_FILE, "r", errors="ignore") as f:
    for linha in f:
        url = linha.strip()
        if not url:
            continue
        total_urls += 1
        for achado in classificar_url(url):
            por_vuln[achado["vuln"]].append(achado)

# gravar arquivos por categoria
prioridade = [
    "IDOR", "SSRF", "Open Redirect", "LFI / RFI",
    "SQL Injection", "Command Injection", "Mass Assignment",
    "JWT / Auth", "XSS"
]

for vuln in prioridade:
    achados = por_vuln.get(vuln, [])
    if not achados:
        continue
    slug = vuln.lower().replace(" ", "_").replace("/", "_")
    arquivo = CLASS_DIR / f"{slug}.txt"
    with open(arquivo, "w") as out:
        out.write(f"# {vuln} — {len(achados)} ocorrências\n")
        out.write("=" * 60 + "\n\n")
        for a in achados:
            valor = a["valor"]
            # destaca parâmetros com valor numérico (mais provável IDOR)
            alerta = " ← VALOR NUMÉRICO" if valor.isdigit() else ""
            out.write(f"PARAM : {a['param']}{alerta}\n")
            out.write(f"URL   : {a['url']}\n")
            out.write("-" * 40 + "\n")

# relatório geral de classificação
relatorio = CLASS_DIR / "resumo_classificacao.md"
with open(relatorio, "w") as r:
    r.write("# Classificação de Parâmetros por Vulnerabilidade\n\n")
    r.write(f"**URLs analisadas:** {total_urls}\n\n")
    r.write("| Vulnerabilidade | Ocorrências | Arquivo |\n")
    r.write("|---|---|---|\n")
    for vuln in prioridade:
        count = len(por_vuln.get(vuln, []))
        if count == 0:
            continue
        slug = vuln.lower().replace(" ", "_").replace("/", "_")
        r.write(f"| {vuln} | {count} | {slug}.txt |\n")
    r.write("\n## Metodologia de teste por tipo\n\n")
    guias = {
        "IDOR": "Troque o valor do parâmetro pelo ID de outro usuário. Teste todos os verbos HTTP (GET/PUT/DELETE).",
        "SSRF": "Aponte o parâmetro para http://169.254.169.254/latest/meta-data/ (AWS metadata). Use Burp Collaborator para blind SSRF.",
        "Open Redirect": "Tente ?redirect=https://evil.com e variações com encoding (%2F%2F, //evil.com).",
        "LFI / RFI": "Teste ../../../etc/passwd, /proc/self/environ, php://filter.",
        "SQL Injection": "Tente ' OR '1'='1, use sqlmap --dbs apenas em escopo autorizado.",
        "Command Injection": "Tente ; id, | whoami, && ls -la após o valor normal.",
        "Mass Assignment": "Adicione campos extras no body do POST/PUT (role=admin, is_admin=true) e veja se são aceitos.",
        "JWT / Auth": "Decodifique o JWT, tente alg:none, force-bruteforce do secret com hashcat.",
        "XSS": "Tente <script>alert(1)</script>, use Burp XSS scan ou dalfox para variações.",
    }
    for vuln, guia in guias.items():
        if len(por_vuln.get(vuln, [])) > 0:
            r.write(f"### {vuln}\n{guia}\n\n")

print(f"[✔] Classificação concluída — {sum(len(v) for v in por_vuln.values())} parâmetros categorizados")
for vuln in prioridade:
    count = len(por_vuln.get(vuln, []))
    if count > 0:
        print(f"    {vuln:25s}: {count}")
PYTHON

    ok "Relatório de classificação: ${CLASS_DIR}/resumo_classificacao.md"
}

# ═════════════════════════════════════════════════════════════
#  FLUXO PRINCIPAL
# ═════════════════════════════════════════════════════════════

if [[ "${MODO}" == "classify" ]]; then
    fase_classificacao
    exit 0
fi

if [[ "${MODO}" == "fuzz" ]]; then
    fase_fuzzing
    exit 0
fi

# ── modo full: inclui recon.sh + fuzzing + classificação ──────
banner "recon-full.sh — Alvo: ${ALVO}"
info "Modo rápido: ${MODO_RAPIDO}"
info "Saída em: ${OUTPUT_DIR}/"

# verificar dependências
banner "Verificando dependências"
DEPS_OK=true
checar_ferramenta subfinder   "github.com/projectdiscovery/subfinder/v2/cmd/subfinder"  || DEPS_OK=false
checar_ferramenta httpx       "github.com/projectdiscovery/httpx/cmd/httpx"              || DEPS_OK=false
checar_ferramenta gau         "github.com/lc/gau/v2/cmd/gau"                             || DEPS_OK=false
checar_ferramenta waybackurls "github.com/tomnomnom/waybackurls"                         || DEPS_OK=false
checar_ferramenta ffuf        "github.com/ffuf/ffuf/v2"                                  || DEPS_OK=false
checar_ferramenta python3     "(padrão do sistema)"                                       || DEPS_OK=false
if ! $MODO_RAPIDO; then
    checar_ferramenta nuclei  "github.com/projectdiscovery/nuclei/v3/cmd/nuclei"         || DEPS_OK=false
fi
$DEPS_OK || { erro "Corrija as dependências acima."; exit 1; }

# ── PASSO 1: subdomínios ──────────────────────────────────────
banner "PASSO 1/6 — Subdomínios"
SUBS_RAW="${OUTPUT_DIR}/subdominios/raw.txt"
info "subfinder..."
subfinder -d "${ALVO}" -silent -o "${SUBS_RAW}" -timeout 30 2>/dev/null || true
echo "${ALVO}" >> "${SUBS_RAW}"
sort -u "${SUBS_RAW}" -o "${SUBS_RAW}"
TOTAL_SUBS=$(wc -l < "${SUBS_RAW}" | tr -d ' ')
ok "Subdomínios: ${TOTAL_SUBS}"

# ── PASSO 2: hosts ativos ─────────────────────────────────────
banner "PASSO 2/6 — Hosts ativos"
HOSTS_ATIVOS="${OUTPUT_DIR}/hosts/ativos.txt"
info "httpx..."
httpx -l "${SUBS_RAW}" -silent -status-code -title -tech-detect \
    -follow-redirects -timeout 10 -retries 2 -threads 50 \
    -o "${HOSTS_ATIVOS}" 2>/dev/null || true
grep -E '\[200\]|\[403\]' "${HOSTS_ATIVOS}" > "${OUTPUT_DIR}/hosts/interessantes.txt" 2>/dev/null || true
TOTAL_ATIVOS=$(wc -l < "${HOSTS_ATIVOS}" | tr -d ' ')
ok "Hosts ativos: ${TOTAL_ATIVOS}"

# ── PASSO 3: parâmetros históricos ────────────────────────────
banner "PASSO 3/6 — Parâmetros históricos"
PARAMS_DIR="${OUTPUT_DIR}/params"
info "waybackurls + gau..."
waybackurls "${ALVO}" 2>/dev/null | sort -u > "${PARAMS_DIR}/wayback.txt" || true
gau "${ALVO}" --threads 5 --retries 3 2>/dev/null | sort -u > "${PARAMS_DIR}/gau.txt" || true
cat "${PARAMS_DIR}/wayback.txt" "${PARAMS_DIR}/gau.txt" | sort -u > "${PARAMS_DIR}/todas.txt"
grep "=" "${PARAMS_DIR}/todas.txt" | sort -u > "${PARAMS_DIR}/com_parametros.txt" || true
grep -iE "\.(bak|sql|log|env|config|conf|xml|json|yaml|yml|gz|zip)$" \
    "${PARAMS_DIR}/todas.txt" > "${PARAMS_DIR}/arquivos_sensiveis.txt" 2>/dev/null || true
TOTAL_PARAMS=$(wc -l < "${PARAMS_DIR}/com_parametros.txt" | tr -d ' ')
ok "URLs com parâmetros: ${TOTAL_PARAMS}"

# ── PASSO 4: nuclei ───────────────────────────────────────────
banner "PASSO 4/6 — Nuclei"
if $MODO_RAPIDO; then
    info "Pulado (--rapido). Rodar depois: nuclei -l ${HOSTS_ATIVOS} -severity medium,high,critical"
else
    nuclei -update-templates -silent 2>/dev/null || true
    nuclei -l "${HOSTS_ATIVOS}" \
        -severity medium,high,critical \
        -tags "exposure,misconfig,cve,xss,sqli,ssrf,idor,auth,lfi" \
        -silent -json \
        -o "${OUTPUT_DIR}/nuclei/findings.json" \
        -o "${OUTPUT_DIR}/nuclei/findings.txt" \
        -timeout 10 -retries 2 -rate-limit 50 2>/dev/null || true
    TOTAL_FINDINGS=$(wc -l < "${OUTPUT_DIR}/nuclei/findings.txt" 2>/dev/null | tr -d ' ')
    ok "Findings nuclei: ${TOTAL_FINDINGS}"
fi

# ── PASSO 5: fuzzing ──────────────────────────────────────────
fase_fuzzing

# ── PASSO 6: classificação ────────────────────────────────────
fase_classificacao

# ── RELATÓRIO FINAL ───────────────────────────────────────────
banner "Relatório Final"
RELATORIO="${OUTPUT_DIR}/relatorio/resumo.md"
cat > "${RELATORIO}" << MARKDOWN
# Relatório de Recon — ${ALVO}
**Data:** $(date "+%d/%m/%Y %H:%M")

## Resumo

| Fase | Resultado |
|---|---|
| Subdomínios | ${TOTAL_SUBS} |
| Hosts ativos | ${TOTAL_ATIVOS} |
| URLs com parâmetros | ${TOTAL_PARAMS} |
| Endpoints fuzzing | $(wc -l < "${OUTPUT_DIR}/fuzzing/todos_endpoints.txt" 2>/dev/null | tr -d ' ') |
| Findings nuclei | $([ "$MODO_RAPIDO" = true ] && echo "pulado" || echo "${TOTAL_FINDINGS:-0}") |

## Onde começar (por prioridade)

1. **${OUTPUT_DIR}/classificacao/idor.txt** — parâmetros com IDs numéricos
2. **${OUTPUT_DIR}/classificacao/ssrf.txt** — parâmetros de URL/endpoint
3. **${OUTPUT_DIR}/classificacao/open_redirect.txt** — redirect/return
4. **${OUTPUT_DIR}/fuzzing/todos_endpoints.txt** — endpoints descobertos
5. **${OUTPUT_DIR}/params/arquivos_sensiveis.txt** — backups/configs expostos

## Aviso legal
Teste realizado com autorização. Invasão sem autorização é crime (art. 154-A CP).
MARKDOWN

echo ""
destaque "══ Recon completo para: ${ALVO} ══"
echo -e "  Relatório:       ${CYAN}${RELATORIO}${NC}"
echo -e "  Classificação:   ${CYAN}${OUTPUT_DIR}/classificacao/resumo_classificacao.md${NC}"
echo -e "  Fuzzing:         ${CYAN}${OUTPUT_DIR}/fuzzing/todos_endpoints.txt${NC}"
echo ""
echo -e "${YELLOW}Próximo passo: carregue no Burp Suite:${NC}"
echo -e "  ${OUTPUT_DIR}/classificacao/idor.txt"
echo -e "  ${OUTPUT_DIR}/classificacao/ssrf.txt"
