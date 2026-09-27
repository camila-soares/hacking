#!/usr/bin/env python3
"""
api.py — Backend Flask do Bug Bounty Toolkit (SecuForge Labs).

Interface web na porta 8080 com endpoints para:
  - Disparar scans (27 ferramentas)
  - Coleta OSINT (crt.sh + theHarvester + SpiderFoot)
  - Geração de relatórios (Markdown / HTML / PDF)
  - Logs em tempo real via SSE
  - Batch scanning (multi-alvo)
  - Agendamentos com cron
  - Integração ngrok
  - Autenticação por API key
  - Rate limiting
  - Persistência SQLite
  - Dashboard com métricas
  - Health check

⚠️  Apenas contra alvos locais ou com autorização escrita (art. 154-A CP).
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import shutil
import sqlite3
import subprocess
import threading
import time
import uuid
from datetime import datetime
from functools import wraps
from pathlib import Path
from typing import Any, Generator

from flask import (
    Flask, Response, jsonify, render_template, request,
    send_from_directory, g,
)

# ---------------------------------------------------------------------------
# Configuração
# ---------------------------------------------------------------------------

app = Flask(__name__, static_folder="static", template_folder="templates")

RESULTADOS_DIR = Path(os.getenv("RESULTADOS_DIR", "/app/resultados"))
RESULTADOS_DIR.mkdir(parents=True, exist_ok=True)

DATA_DIR = Path(os.getenv("SECUFORGE_DATA_DIR", "/app/data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)

DB_PATH = DATA_DIR / "secuforge.db"
KEY_FILE = DATA_DIR / "api.key"

# Rate limiting
try:
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address
    limiter = Limiter(
        get_remote_address,
        app=app,
        default_limits=["200 per minute"],
        storage_uri="memory://",
    )
except ImportError:
    limiter = None

TOOLS_BY_CATEGORY = {
    "Recon & Enumeração": [
        "nmap", "masscan", "rustscan", "subfinder", "amass", "httpx",
        "ffuf", "gobuster", "dirsearch", "wfuzz", "waybackurls", "gau",
        "dnsrecon", "fierce",
    ],
    "Vulnerability Scanning": [
        "nuclei", "nikto", "whatweb", "wpscan", "testssl.sh", "sslscan",
    ],
    "Exploit & Injection": [
        "sqlmap", "commix", "xsstrike", "dalfox",
    ],
    "Brute Force & Cracking": [
        "hydra", "john", "hashcat",
    ],
    "Network Analysis": [
        "tshark", "enum4linux",
    ],
}

ALLOWED_TOOLS = set()
for tools in TOOLS_BY_CATEGORY.values():
    ALLOWED_TOOLS.update(tools)

# Alvos locais seguros (Docker lab)
SAFE_TARGETS = {
    "dvwa", "juice-shop", "juiceshop", "webgoat",
    "localhost", "127.0.0.1", "10.", "172.16.", "172.17.",
    "172.18.", "172.19.", "172.20.", "192.168.",
}

# Estado em memória (logs SSE — não persiste, pois são efêmeros)
_scan_logs: dict[str, list[str]] = {}
_scan_lock = threading.Lock()


# ---------------------------------------------------------------------------
# SQLite — Persistência
# ---------------------------------------------------------------------------

def _get_db() -> sqlite3.Connection:
    """Retorna conexão SQLite thread-local."""
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(str(DB_PATH))
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA foreign_keys=ON")
    return db


@app.teardown_appcontext
def _close_db(exception):
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()


def _db_conn() -> sqlite3.Connection:
    """Conexão fora de contexto Flask (para threads de background)."""
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def _init_db():
    """Cria tabelas se não existirem."""
    conn = sqlite3.connect(str(DB_PATH))
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS scans (
            scan_id   TEXT PRIMARY KEY,
            tool      TEXT NOT NULL,
            target    TEXT NOT NULL,
            dominio   TEXT,
            modo      TEXT DEFAULT 'rapido',
            tipo      TEXT DEFAULT 'dominio',
            url_base  TEXT,
            safe_target INTEGER DEFAULT 0,
            status    TEXT DEFAULT 'rodando',
            inicio    TEXT,
            fim       TEXT,
            batch_id  TEXT,
            schedule_id TEXT,
            output_dir TEXT,
            created_at TEXT DEFAULT (datetime('now','localtime'))
        );

        CREATE TABLE IF NOT EXISTS batches (
            batch_id     TEXT PRIMARY KEY,
            alvos        TEXT,
            modo         TEXT DEFAULT 'rapido',
            tool         TEXT DEFAULT 'nmap',
            concorrencia INTEGER DEFAULT 3,
            status       TEXT DEFAULT 'rodando',
            inicio       TEXT,
            fim          TEXT,
            created_at   TEXT DEFAULT (datetime('now','localtime'))
        );

        CREATE TABLE IF NOT EXISTS schedules (
            id      TEXT PRIMARY KEY,
            alvo    TEXT NOT NULL,
            modo    TEXT DEFAULT 'rapido',
            cron    TEXT NOT NULL,
            nome    TEXT,
            ativo   INTEGER DEFAULT 1,
            proxima TEXT,
            ultima_execucao TEXT,
            criado  TEXT,
            created_at TEXT DEFAULT (datetime('now','localtime'))
        );

        CREATE TABLE IF NOT EXISTS dashboard_stats (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id    TEXT,
            tool       TEXT,
            target     TEXT,
            status     TEXT,
            severity   TEXT,
            vuln_count INTEGER DEFAULT 0,
            duration_s REAL DEFAULT 0,
            recorded_at TEXT DEFAULT (datetime('now','localtime'))
        );
    """)
    conn.commit()
    conn.close()


_init_db()


# ---------------------------------------------------------------------------
# Autenticação por API Key
# ---------------------------------------------------------------------------

def _get_or_create_api_key() -> str:
    """Lê a chave de api.key ou gera uma nova."""
    if KEY_FILE.exists():
        return KEY_FILE.read_text(encoding="utf-8").strip()
    key = secrets.token_urlsafe(32)
    KEY_FILE.write_text(key, encoding="utf-8")
    print(f"🔑 API Key gerada: {key}")
    print(f"   Salva em: {KEY_FILE}")
    return key


API_KEY = _get_or_create_api_key()
AUTH_ENABLED = os.getenv("SECUFORGE_AUTH", "true").lower() in ("true", "1", "yes")

# Rotas que não precisam de autenticação
PUBLIC_ROUTES = {"/", "/api/health", "/api/auth/login", "/api/auth/status"}


def require_auth(f):
    """Decorator que exige API key válida."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not AUTH_ENABLED:
            return f(*args, **kwargs)

        # Checar header ou query param
        key = request.headers.get("X-API-Key") or request.args.get("api_key")

        # Checar cookie de sessão
        if not key:
            session_token = request.cookies.get("secuforge_session")
            if session_token:
                expected = hashlib.sha256(API_KEY.encode()).hexdigest()
                if session_token == expected:
                    return f(*args, **kwargs)

        if not key:
            return jsonify({"erro": "Autenticação necessária. Envie X-API-Key no header."}), 401
        if key != API_KEY:
            return jsonify({"erro": "API Key inválida."}), 403
        return f(*args, **kwargs)
    return decorated


@app.before_request
def _check_auth():
    """Verifica autenticação globalmente para rotas de API (exceto públicas)."""
    if not AUTH_ENABLED:
        return
    path = request.path
    # Rotas públicas
    if path in PUBLIC_ROUTES:
        return
    # Arquivos estáticos
    if path.startswith("/static/"):
        return
    # Rotas de API exigem auth
    if path.startswith("/api/"):
        key = request.headers.get("X-API-Key") or request.args.get("api_key")
        session_token = request.cookies.get("secuforge_session")
        if key == API_KEY:
            return
        if session_token:
            expected = hashlib.sha256(API_KEY.encode()).hexdigest()
            if session_token == expected:
                return
        return jsonify({"erro": "Autenticação necessária."}), 401


@app.route("/api/auth/login", methods=["POST"])
def auth_login():
    """Login — recebe {key} e retorna cookie de sessão."""
    data = request.get_json(force=True, silent=True) or {}
    key = data.get("key", "").strip()
    if key != API_KEY:
        return jsonify({"ok": False, "erro": "Chave inválida."}), 403
    resp = jsonify({"ok": True})
    session_hash = hashlib.sha256(API_KEY.encode()).hexdigest()
    resp.set_cookie("secuforge_session", session_hash,
                    httponly=True, samesite="Strict", max_age=86400 * 7)
    return resp


@app.route("/api/auth/status")
def auth_status():
    """Verifica se a sessão atual está autenticada."""
    if not AUTH_ENABLED:
        return jsonify({"authenticated": True, "auth_enabled": False})
    session_token = request.cookies.get("secuforge_session")
    key = request.headers.get("X-API-Key") or request.args.get("api_key")
    authenticated = False
    if key == API_KEY:
        authenticated = True
    elif session_token:
        expected = hashlib.sha256(API_KEY.encode()).hexdigest()
        authenticated = session_token == expected
    return jsonify({"authenticated": authenticated, "auth_enabled": True})


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ts() -> str:
    """Timestamp no formato YYYYMMDD_HHMMSS."""
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def _new_id() -> str:
    return _ts() + "-" + uuid.uuid4().hex[:6]


def _log(scan_id: str, msg: str) -> None:
    ts = datetime.now().strftime("%H:%M:%S")
    line = f"[{ts}] {msg}"
    with _scan_lock:
        _scan_logs.setdefault(scan_id, []).append(line)
    print(line, flush=True)


def _is_target_safe(target: str) -> bool:
    t = target.lower().strip()
    for safe in SAFE_TARGETS:
        if t.startswith(safe) or safe in t:
            return True
    return False


def _validate_target(target: str) -> str | None:
    if not target or not target.strip():
        return "Alvo não pode ser vazio."
    if any(c in target for c in [";", "&", "|", "`", "$", "(", ")", "{", "}"]):
        return "Caracteres não permitidos no alvo."
    return None


def _validate_tool(tool: str) -> str | None:
    if tool not in ALLOWED_TOOLS:
        return f"Ferramenta '{tool}' não é permitida."
    return None


def _detect_tipo(alvo: str) -> tuple[str, str, str | None]:
    """Detecta se é URL ou domínio. Retorna (tipo, dominio, url_base|None)."""
    if alvo.startswith("http://") or alvo.startswith("https://"):
        match = re.match(r"https?://([^/:]+)", alvo)
        dominio = match.group(1) if match else alvo
        return "url", dominio, alvo
    return "dominio", alvo, None


# ---------------------------------------------------------------------------
# Construtor de comandos
# ---------------------------------------------------------------------------

def _build_command(tool: str, target: str, options: dict[str, Any],
                   output_dir: Path) -> list[str]:
    out_file = str(output_dir / f"{tool}-output")

    if tool == "nmap":
        ports = options.get("ports", "1-1000")
        return ["nmap", "-sV", "-p", str(ports), "-oN", f"{out_file}.txt",
                "-oX", f"{out_file}.xml", target]

    if tool == "nuclei":
        severity = options.get("severity", "critical,high,medium")
        return ["nuclei", "-u", target, "-severity", severity,
                "-o", f"{out_file}.txt", "-silent"]

    if tool == "ffuf":
        wordlist = options.get("wordlist", "/usr/share/wordlists/common.txt")
        return ["ffuf", "-u", f"{target}/FUZZ", "-w", wordlist,
                "-o", f"{out_file}.json", "-of", "json", "-s"]

    if tool == "nikto":
        return ["nikto", "-h", target, "-o", f"{out_file}.html",
                "-Format", "htm", "-nointeractive"]

    if tool == "whatweb":
        return ["whatweb", "--log-json", f"{out_file}.json", target]

    if tool == "tshark":
        duration = options.get("duration", "30")
        return ["tshark", "-a", f"duration:{duration}", "-w", f"{out_file}.pcap"]

    if tool == "sqlmap":
        return ["sqlmap", "-u", target, "--batch", "--output-dir",
                str(output_dir / "sqlmap")]

    if tool == "subfinder":
        return ["subfinder", "-d", target, "-o", f"{out_file}.txt", "-silent"]

    if tool == "amass":
        return ["amass", "enum", "-passive", "-d", target, "-o", f"{out_file}.txt"]

    if tool == "httpx":
        return ["httpx", "-u", target, "-status-code", "-title",
                "-tech-detect", "-o", f"{out_file}.txt", "-silent"]

    if tool == "gobuster":
        wordlist = options.get("wordlist", "/usr/share/wordlists/common.txt")
        return ["gobuster", "dir", "-u", target, "-w", wordlist,
                "-o", f"{out_file}.txt", "-q"]

    if tool == "dirsearch":
        return ["dirsearch", "-u", target, "--format", "json",
                "-o", f"{out_file}.json", "-q"]

    if tool == "wfuzz":
        wordlist = options.get("wordlist", "/usr/share/wordlists/common.txt")
        return ["wfuzz", "-c", "-z", f"file,{wordlist}", "--hc", "404",
                "-f", f"{out_file}.json,json", f"{target}/FUZZ"]

    if tool == "waybackurls":
        return ["sh", "-c", f"echo {target} | waybackurls > {out_file}.txt"]

    if tool == "gau":
        return ["sh", "-c", f"echo {target} | gau --o {out_file}.txt"]

    if tool == "dnsrecon":
        return ["dnsrecon", "-d", target, "-j", f"{out_file}.json"]

    if tool == "fierce":
        return ["fierce", "--domain", target, "--file", f"{out_file}.txt"]

    if tool == "masscan":
        ports = options.get("ports", "1-1000")
        rate = options.get("rate", "1000")
        return ["masscan", target, "-p", str(ports), "--rate", str(rate),
                "-oJ", f"{out_file}.json"]

    if tool == "rustscan":
        return ["rustscan", "-a", target, "--ulimit", "5000",
                "--", "-sV", "-oN", f"{out_file}.txt"]

    if tool == "wpscan":
        return ["wpscan", "--url", target, "--no-banner",
                "-o", f"{out_file}.json", "-f", "json"]

    if tool == "testssl.sh":
        return ["testssl.sh", "--jsonfile", f"{out_file}.json", target]

    if tool == "sslscan":
        return ["sslscan", f"--xml={out_file}.xml", target]

    if tool == "commix":
        return ["commix", "--url", target, "--batch",
                "--output-dir", str(output_dir / "commix")]

    if tool == "xsstrike":
        return ["xsstrike", "-u", target, "--skip",
                "--log-file", f"{out_file}.log"]

    if tool == "dalfox":
        return ["dalfox", "url", target, "-o", f"{out_file}.txt", "--silence"]

    if tool == "hydra":
        service = options.get("service", "http-post-form")
        user = options.get("user", "admin")
        wordlist = options.get("wordlist", "/usr/share/wordlists/rockyou.txt")
        return ["hydra", "-l", user, "-P", wordlist, target, service,
                "-o", f"{out_file}.txt"]

    if tool == "john":
        hash_file = options.get("hash_file", "")
        if not hash_file:
            return []
        return ["john", hash_file, f"--pot={out_file}.pot"]

    if tool == "hashcat":
        hash_file = options.get("hash_file", "")
        mode = options.get("mode", "0")
        wordlist = options.get("wordlist", "/usr/share/wordlists/rockyou.txt")
        if not hash_file:
            return []
        return ["hashcat", "-m", str(mode), hash_file, wordlist,
                f"--outfile={out_file}.txt"]

    if tool == "enum4linux":
        return ["enum4linux", "-a", target, "-o", f"{out_file}.txt"]

    return []


# ---------------------------------------------------------------------------
# Execução de scan em background
# ---------------------------------------------------------------------------

def _executar_scan(scan_id: str, tool: str, target: str,
                   modo: str, options: dict[str, Any]) -> None:
    output_dir = RESULTADOS_DIR / scan_id
    output_dir.mkdir(parents=True, exist_ok=True)

    conn = _db_conn()
    conn.execute("UPDATE scans SET status='rodando', output_dir=? WHERE scan_id=?",
                 (str(output_dir), scan_id))
    conn.commit()

    start_time = time.time()
    _log(scan_id, f"[→] Iniciando {tool} contra {target} (modo: {modo})...")

    # --- OSINT automático (se domínio) ---
    if re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", target):
        try:
            import osint
            _log(scan_id, "[→] OSINT (crt.sh + theHarvester)...")
            dados = osint.collect(target)
            (output_dir / "osint.json").write_text(
                json.dumps(dados, ensure_ascii=False, indent=2), encoding="utf-8")
            _log(scan_id, f"[✔] OSINT: {len(dados.get('subdomains', []))} subs, "
                          f"{len(dados.get('emails', []))} e-mails")
        except Exception as e:
            _log(scan_id, f"[!] OSINT: {e}")

    # --- Scan principal ---
    cmd = _build_command(tool, target, options, output_dir)
    if not cmd:
        _log(scan_id, f"[!] Comando não configurado para {tool}")
        conn.execute("UPDATE scans SET status='erro', fim=? WHERE scan_id=?",
                     (_ts(), scan_id))
        conn.commit()
        conn.close()
        return

    _log(scan_id, f"[→] $ {' '.join(cmd)}")
    final_status = "concluido"
    vuln_count = 0

    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=int(options.get("timeout", 600)),
        )
        (output_dir / f"{tool}-stdout.txt").write_text(proc.stdout, encoding="utf-8")
        if proc.stderr:
            (output_dir / f"{tool}-stderr.txt").write_text(proc.stderr, encoding="utf-8")

        if proc.returncode == 0:
            _log(scan_id, f"[✔] {tool} finalizado com sucesso.")
        else:
            _log(scan_id, f"[!] {tool} retornou código {proc.returncode}.")

        # Tentar contar vulnerabilidades no output
        try:
            stdout_lower = proc.stdout.lower()
            vuln_count = (stdout_lower.count("critical") + stdout_lower.count("high")
                          + stdout_lower.count("medium") + stdout_lower.count("vulnerability"))
        except Exception:
            pass

    except subprocess.TimeoutExpired:
        _log(scan_id, f"[!] {tool} excedeu o timeout.")
        final_status = "erro"
    except FileNotFoundError:
        _log(scan_id, f"[!] {tool} não encontrado no PATH.")
        final_status = "erro"
    except Exception as exc:
        _log(scan_id, f"[!] Erro inesperado: {exc}")
        final_status = "erro"

    fim = _ts()
    duration = time.time() - start_time

    conn.execute("UPDATE scans SET status=?, fim=? WHERE scan_id=?",
                 (final_status, fim, scan_id))

    # Registrar no dashboard_stats
    conn.execute("""INSERT INTO dashboard_stats (scan_id, tool, target, status, vuln_count, duration_s)
                    VALUES (?, ?, ?, ?, ?, ?)""",
                 (scan_id, tool, target, final_status, vuln_count, round(duration, 1)))
    conn.commit()

    # Gera relatório HTML automaticamente
    try:
        _gerar_relatorio_html(scan_id, tool, target, output_dir)
        _log(scan_id, "[✔] Relatório HTML gerado.")
    except Exception as e:
        _log(scan_id, f"[!] Erro no relatório: {e}")

    # Salva metadados
    meta = {
        "scan_id": scan_id, "tool": tool, "target": target,
        "modo": modo, "status": final_status,
        "inicio": conn.execute("SELECT inicio FROM scans WHERE scan_id=?",
                               (scan_id,)).fetchone()["inicio"],
        "fim": fim,
        "duration_s": round(duration, 1),
    }
    (output_dir / "scan-meta.json").write_text(
        json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")

    conn.close()


def _gerar_relatorio_html(scan_id: str, tool: str, target: str,
                          output_dir: Path) -> None:
    """Gera um relatório HTML simples com os resultados do scan."""
    files = []
    for f in sorted(output_dir.iterdir()):
        if f.is_file() and f.suffix in (".txt", ".json", ".xml", ".html", ".log"):
            try:
                content = f.read_text(encoding="utf-8", errors="replace")[:50000]
            except Exception:
                content = "(erro ao ler)"
            files.append((f.name, content))

    html = f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<title>Relatório — {tool} — {target}</title>
<style>
body {{ background:#0f0f23; color:#ecf0f1; font-family:'Segoe UI',sans-serif;
       padding:24px; max-width:1000px; margin:auto; }}
h1 {{ color:#00d4ff; font-size:20px; }}
h2 {{ color:#3498db; font-size:16px; margin-top:24px; }}
pre {{ background:#1a1a2e; border:1px solid #2d2d4e; border-radius:8px;
       padding:14px; overflow-x:auto; font-size:12px; line-height:1.5;
       white-space:pre-wrap; word-break:break-all; }}
.meta {{ color:#7f8c8d; font-size:13px; margin-bottom:20px; }}
.warn {{ background:#1c0a00; border:1px solid #e67e22; border-radius:6px;
         padding:10px; font-size:12px; color:#e67e22; margin-top:20px; }}
.btn-pdf {{ display:inline-block; margin-top:16px; padding:10px 20px;
            background:#00d4ff; color:#0f0f23; border-radius:6px;
            text-decoration:none; font-weight:600; font-size:13px; }}
.btn-pdf:hover {{ opacity:.85; }}
</style>
</head>
<body>
<h1>Relatório — {tool}</h1>
<div class="meta">
  Alvo: <strong>{target}</strong> &nbsp;|&nbsp;
  Scan ID: {scan_id} &nbsp;|&nbsp;
  Data: {datetime.now().strftime("%d/%m/%Y %H:%M")}
</div>
<a class="btn-pdf" href="/api/scans/{scan_id}/report?format=pdf" target="_blank">&#128196; Baixar PDF</a>
"""
    for fname, content in files:
        html += f'<h2>{fname}</h2>\n<pre>{content}</pre>\n'

    html += """
<div class="warn">
  ⚠️ Documento confidencial. Apenas alvos com autorização escrita (art. 154-A CP).
</div>
</body></html>"""

    (output_dir / "report.html").write_text(html, encoding="utf-8")


# ---------------------------------------------------------------------------
# Rotas — API
# ---------------------------------------------------------------------------

@app.route("/api/health")
def health():
    return jsonify({"status": "ok", "timestamp": datetime.now().isoformat(),
                    "auth_enabled": AUTH_ENABLED})


@app.route("/api/tools")
def list_tools():
    """Lista ferramentas — retorna {nome: {ok, versao, categoria}}."""
    result = {}
    for cat, tools in TOOLS_BY_CATEGORY.items():
        for tool in tools:
            path = shutil.which(tool)
            versao = ""
            if path:
                try:
                    v = subprocess.run([tool, "--version"], capture_output=True,
                                       text=True, timeout=5)
                    versao = (v.stdout or v.stderr or "").strip().split("\n")[0][:80]
                except Exception:
                    versao = path
            result[tool] = {
                "ok": path is not None,
                "versao": versao if path else "",
                "categoria": cat,
            }
    return jsonify(result)


# ── Scans ────────────────────────────────────────────────────────────────

@app.route("/api/scans", methods=["GET", "POST"])
def scans_endpoint():
    """GET = listar scans, POST = iniciar scan."""
    if request.method == "GET":
        db = _get_db()
        rows = db.execute(
            "SELECT scan_id, dominio, modo, tool, status, inicio, fim "
            "FROM scans ORDER BY created_at DESC LIMIT 100"
        ).fetchall()
        result = []
        for r in rows:
            result.append({
                "id": r["scan_id"],
                "dominio": r["dominio"] or r["tool"],
                "modo": r["modo"],
                "tool": r["tool"],
                "status": r["status"],
                "inicio": r["inicio"] or "",
                "fim": r["fim"] or "",
            })
        return jsonify(result)

    # POST — iniciar scan
    data = request.get_json(force=True, silent=True) or {}
    alvo = data.get("alvo", "").strip()
    modo = data.get("modo", "rapido")
    tool = data.get("tool", "")

    if not tool:
        tool = "nuclei" if modo == "completo" else "nmap"

    err = _validate_target(alvo)
    if err:
        return jsonify({"erro": err}), 400

    err = _validate_tool(tool)
    if err:
        return jsonify({"erro": err}), 400

    tipo, dominio, url_base = _detect_tipo(alvo)
    target = alvo if tipo == "url" else dominio
    safe = _is_target_safe(target)

    scan_id = _new_id()
    inicio = _ts()

    db = _get_db()
    db.execute("""INSERT INTO scans (scan_id, tool, target, dominio, modo, tipo,
                  url_base, safe_target, status, inicio)
                  VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'rodando', ?)""",
               (scan_id, tool, target, dominio, modo, tipo,
                url_base, 1 if safe else 0, inicio))
    db.commit()

    if not safe:
        _log(scan_id, "⚠️  Alvo externo — certifique-se de ter autorização escrita "
                       "(art. 154-A CP, Lei 12.737/2012).")

    options = data.get("options", {})
    thread = threading.Thread(
        target=_executar_scan, args=(scan_id, tool, target, modo, options),
        daemon=True,
    )
    thread.start()

    return jsonify({
        "scan_id": scan_id,
        "tipo": tipo,
        "dominio": dominio,
        "url_base": url_base,
        "status": "rodando",
    }), 202


@app.route("/api/scans/<scan_id>", methods=["GET", "DELETE"])
def scan_detail(scan_id: str):
    if request.method == "DELETE":
        db = _get_db()
        cur = db.execute("DELETE FROM scans WHERE scan_id=?", (scan_id,))
        db.commit()
        if cur.rowcount == 0:
            return jsonify({"erro": "Scan não encontrado."}), 404
        with _scan_lock:
            _scan_logs.pop(scan_id, None)
        return jsonify({"ok": True})

    db = _get_db()
    row = db.execute("SELECT * FROM scans WHERE scan_id=?", (scan_id,)).fetchone()
    if not row:
        return jsonify({"erro": "Scan não encontrado."}), 404
    return jsonify(dict(row))


@app.route("/api/scans/<scan_id>/log")
def scan_log_sse(scan_id: str) -> Response:
    """SSE — logs em tempo real (formato: {linha} e {fim})."""
    def generate() -> Generator[str, None, None]:
        last_idx = 0
        while True:
            with _scan_lock:
                logs = _scan_logs.get(scan_id, [])
            for line in logs[last_idx:]:
                yield f"data: {json.dumps({'linha': line})}\n\n"
            last_idx = len(logs)

            # Verificar status no banco
            conn = _db_conn()
            row = conn.execute("SELECT status FROM scans WHERE scan_id=?",
                               (scan_id,)).fetchone()
            conn.close()
            if not row or row["status"] in ("concluido", "erro"):
                yield f"data: {json.dumps({'fim': True})}\n\n"
                break
            time.sleep(1)

    return Response(generate(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache",
                             "X-Accel-Buffering": "no"})


@app.route("/api/scans/<scan_id>/report")
def scan_report(scan_id: str):
    """Retorna relatório HTML ou PDF do scan."""
    fmt = request.args.get("format", "html").lower()
    output_dir = RESULTADOS_DIR / scan_id
    report_html = output_dir / "report.html"

    if not report_html.exists():
        return "<h2>Relatório não disponível</h2>", 404

    if fmt == "pdf":
        report_pdf = output_dir / "report.pdf"
        if not report_pdf.exists():
            try:
                from weasyprint import HTML as WeasyHTML
                WeasyHTML(filename=str(report_html)).write_pdf(str(report_pdf))
            except ImportError:
                # Fallback: wkhtmltopdf
                try:
                    subprocess.run(["wkhtmltopdf", "--quiet",
                                    str(report_html), str(report_pdf)],
                                   timeout=30, check=True)
                except Exception:
                    return jsonify({"erro": "WeasyPrint/wkhtmltopdf não disponível."}), 500
            except Exception as e:
                return jsonify({"erro": f"Erro gerando PDF: {e}"}), 500
        return send_from_directory(str(output_dir), "report.pdf",
                                   mimetype="application/pdf")

    return send_from_directory(str(output_dir), "report.html")


@app.route("/api/scan/<scan_id>/results")
def scan_results(scan_id: str):
    output_dir = RESULTADOS_DIR / scan_id
    if not output_dir.exists():
        return jsonify({"error": "Resultados não encontrados."}), 404
    files = []
    for f in sorted(output_dir.iterdir()):
        if f.is_file():
            files.append({
                "name": f.name,
                "size": f.stat().st_size,
                "url": f"/api/scan/{scan_id}/file/{f.name}",
            })
    return jsonify({"scan_id": scan_id, "files": files})


@app.route("/api/scan/<scan_id>/file/<filename>")
def scan_file(scan_id: str, filename: str):
    output_dir = RESULTADOS_DIR / scan_id
    if not output_dir.exists():
        return jsonify({"error": "Não encontrado."}), 404
    safe_name = Path(filename).name
    return send_from_directory(str(output_dir), safe_name)


# ── Batch (multi-alvo) ──────────────────────────────────────────────────

_batch_rate = "5 per minute" if limiter else None

@app.route("/api/scans/batch", methods=["POST"])
def batch_scan():
    data = request.get_json(force=True, silent=True) or {}
    alvos = data.get("alvos", [])
    modo = data.get("modo", "rapido")
    concorrencia = min(int(data.get("concorrencia", 3)), 5)
    tool = data.get("tool", "")

    if not tool:
        tool = "nuclei" if modo == "completo" else "nmap"

    if not alvos or not isinstance(alvos, list):
        return jsonify({"erro": "Informe uma lista de alvos."}), 400

    batch_id = "batch-" + _new_id()

    db = _get_db()
    db.execute("""INSERT INTO batches (batch_id, alvos, modo, tool, concorrencia, status, inicio)
                  VALUES (?, ?, ?, ?, ?, 'rodando', ?)""",
               (batch_id, json.dumps(alvos), modo, tool, concorrencia, _ts()))
    db.commit()

    sem = threading.Semaphore(concorrencia)

    def _run_batch_item(alvo: str):
        with sem:
            tipo, dominio, url_base = _detect_tipo(alvo)
            target = alvo if tipo == "url" else dominio
            safe = _is_target_safe(target)
            sid = _new_id()

            conn = _db_conn()
            conn.execute("""INSERT INTO scans (scan_id, tool, target, dominio, modo,
                            tipo, url_base, safe_target, status, inicio, batch_id)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'rodando', ?, ?)""",
                         (sid, tool, target, dominio, modo, tipo,
                          url_base, 1 if safe else 0, _ts(), batch_id))
            conn.commit()
            conn.close()

            _executar_scan(sid, tool, target, modo, {})

    threads = []
    for alvo in alvos:
        t = threading.Thread(target=_run_batch_item, args=(alvo.strip(),), daemon=True)
        threads.append(t)
        t.start()

    def _wait_batch():
        for t in threads:
            t.join()
        conn = _db_conn()
        conn.execute("UPDATE batches SET status='concluido', fim=? WHERE batch_id=?",
                     (_ts(), batch_id))
        conn.commit()
        conn.close()

    threading.Thread(target=_wait_batch, daemon=True).start()

    return jsonify({
        "batch_id": batch_id,
        "total": len(alvos),
        "status": "rodando",
    }), 202


@app.route("/api/batches")
def list_batches():
    db = _get_db()
    rows = db.execute(
        "SELECT * FROM batches ORDER BY created_at DESC LIMIT 50"
    ).fetchall()
    result = []
    for r in rows:
        d = dict(r)
        d["alvos"] = json.loads(d.get("alvos") or "[]")
        # Contar scan_ids do batch
        scan_ids = db.execute(
            "SELECT scan_id FROM scans WHERE batch_id=?", (d["batch_id"],)
        ).fetchall()
        d["scan_ids"] = [s["scan_id"] for s in scan_ids]
        result.append(d)
    return jsonify(result)


# ── Agendamentos ────────────────────────────────────────────────────────

@app.route("/api/schedules", methods=["GET", "POST"])
def schedules_endpoint():
    if request.method == "GET":
        db = _get_db()
        rows = db.execute("SELECT * FROM schedules WHERE ativo=1 ORDER BY created_at DESC").fetchall()
        return jsonify([dict(r) for r in rows])

    data = request.get_json(force=True, silent=True) or {}
    alvo = data.get("alvo", "").strip()
    modo = data.get("modo", "rapido")
    cron = data.get("cron", "").strip()
    nome = data.get("nome", "").strip()

    if not alvo:
        return jsonify({"erro": "Informe o alvo."}), 400
    if not cron:
        return jsonify({"erro": "Informe a expressão cron."}), 400

    campos = cron.split()
    if len(campos) != 5:
        return jsonify({"erro": "Expressão cron deve ter 5 campos."}), 400

    sched_id = "sched-" + uuid.uuid4().hex[:8]
    proxima = _calcular_proxima(cron)

    db = _get_db()
    db.execute("""INSERT INTO schedules (id, alvo, modo, cron, nome, ativo, proxima, criado)
                  VALUES (?, ?, ?, ?, ?, 1, ?, ?)""",
               (sched_id, alvo, modo, cron, nome or alvo, proxima, _ts()))
    db.commit()

    threading.Thread(target=_schedule_runner, args=(sched_id,), daemon=True).start()

    return jsonify({
        "id": sched_id,
        "proxima": proxima,
    }), 201


@app.route("/api/schedules/<sched_id>", methods=["DELETE"])
def delete_schedule(sched_id: str):
    db = _get_db()
    cur = db.execute("DELETE FROM schedules WHERE id=?", (sched_id,))
    db.commit()
    if cur.rowcount == 0:
        return jsonify({"erro": "Agendamento não encontrado."}), 404
    return jsonify({"ok": True})


def _calcular_proxima(cron_expr: str) -> str:
    try:
        from croniter import croniter
        cron = croniter(cron_expr, datetime.now())
        return cron.get_next(datetime).strftime("%d/%m/%Y %H:%M")
    except Exception:
        return "próxima iteração"


def _schedule_runner(sched_id: str):
    while True:
        conn = _db_conn()
        row = conn.execute("SELECT * FROM schedules WHERE id=? AND ativo=1",
                           (sched_id,)).fetchone()
        conn.close()
        if not row:
            break
        try:
            from croniter import croniter
            cron = croniter(row["cron"], datetime.now())
            next_run = cron.get_next(datetime)
            wait = (next_run - datetime.now()).total_seconds()
            if wait > 0:
                time.sleep(min(wait, 3600))
                # Verificar se ainda ativo
                conn = _db_conn()
                r2 = conn.execute("SELECT ativo FROM schedules WHERE id=?",
                                  (sched_id,)).fetchone()
                if not r2 or not r2["ativo"]:
                    conn.close()
                    break
                # Disparar scan
                alvo = row["alvo"]
                modo = row["modo"]
                tool = "nuclei" if modo == "completo" else "nmap"
                tipo, dominio, url_base = _detect_tipo(alvo)
                target = alvo if tipo == "url" else dominio
                sid = _new_id()
                conn.execute("""INSERT INTO scans (scan_id, tool, target, dominio, modo,
                                tipo, url_base, safe_target, status, inicio, schedule_id)
                                VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'rodando', ?, ?)""",
                             (sid, tool, target, dominio, modo, tipo,
                              url_base, 1 if _is_target_safe(target) else 0,
                              _ts(), sched_id))
                conn.execute("UPDATE schedules SET ultima_execucao=?, proxima=? WHERE id=?",
                             (_ts(), _calcular_proxima(row["cron"]), sched_id))
                conn.commit()
                conn.close()
                _executar_scan(sid, tool, target, modo, {})
        except ImportError:
            time.sleep(3600)
        except Exception:
            time.sleep(60)


# ── ngrok ───────────────────────────────────────────────────────────────

@app.route("/api/ngrok-url")
def ngrok_url():
    try:
        import urllib.request
        r = urllib.request.urlopen("http://127.0.0.1:4040/api/tunnels", timeout=2)
        data = json.loads(r.read())
        tunnels = data.get("tunnels", [])
        for t in tunnels:
            if t.get("proto") == "https":
                return jsonify({"url": t["public_url"]})
        if tunnels:
            return jsonify({"url": tunnels[0].get("public_url", "")})
    except Exception:
        pass
    return jsonify({"url": None})


# ── OSINT ───────────────────────────────────────────────────────────────

@app.route("/api/osint", methods=["POST"])
def run_osint():
    data = request.get_json(force=True, silent=True) or {}
    target = data.get("target", data.get("alvo", "")).strip()
    err = _validate_target(target)
    if err:
        return jsonify({"error": err}), 400
    try:
        import osint
        resultado = osint.collect(target)
        return jsonify(resultado)
    except ImportError:
        return jsonify({"error": "Módulo osint.py não encontrado."}), 500
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/osint/spiderfoot", methods=["POST"])
def run_spiderfoot():
    data = request.get_json(force=True, silent=True) or {}
    target = data.get("target", data.get("alvo", "")).strip()
    err = _validate_target(target)
    if err:
        return jsonify({"error": err}), 400
    try:
        import spiderfoot_client
        resultado = spiderfoot_client.run(target, progress=False)
        return jsonify(resultado)
    except ImportError:
        return jsonify({"error": "SpiderFoot não disponível. "
                        "docker compose --profile osint up -d spiderfoot"}), 500
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


# ── Relatório ───────────────────────────────────────────────────────────

@app.route("/api/report", methods=["POST"])
def generate_report():
    data = request.get_json(force=True, silent=True) or {}
    meta = data.get("meta", {})
    findings = data.get("findings", [])
    consolidated = data.get("consolidated", {})
    fmt = data.get("format", "md").lower()

    if fmt not in ("md", "html", "pdf"):
        return jsonify({"error": "Formato deve ser md, html ou pdf."}), 400

    try:
        import laudo
        report_id = _new_id()
        output_dir = RESULTADOS_DIR / f"report-{report_id}"
        output_dir.mkdir(parents=True, exist_ok=True)
        output_file = str(output_dir / f"relatorio.{fmt}")
        laudo.generate(meta, consolidated, findings, output_file)
        return jsonify({
            "report_id": report_id,
            "file": f"/api/scan/report-{report_id}/file/relatorio.{fmt}",
            "format": fmt,
        })
    except ImportError:
        return jsonify({"error": "Módulo laudo.py não encontrado."}), 500
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


# ── Dashboard ───────────────────────────────────────────────────────────

@app.route("/api/dashboard")
def dashboard_stats():
    """Retorna métricas para o dashboard."""
    db = _get_db()

    total = db.execute("SELECT COUNT(*) as c FROM scans").fetchone()["c"]
    rodando = db.execute("SELECT COUNT(*) as c FROM scans WHERE status='rodando'").fetchone()["c"]
    concluidos = db.execute("SELECT COUNT(*) as c FROM scans WHERE status='concluido'").fetchone()["c"]
    erros = db.execute("SELECT COUNT(*) as c FROM scans WHERE status='erro'").fetchone()["c"]

    # Ferramentas mais usadas
    top_tools = db.execute("""
        SELECT tool, COUNT(*) as c FROM scans
        GROUP BY tool ORDER BY c DESC LIMIT 10
    """).fetchall()

    # Alvos mais escaneados
    top_targets = db.execute("""
        SELECT dominio, COUNT(*) as c FROM scans
        GROUP BY dominio ORDER BY c DESC LIMIT 10
    """).fetchall()

    # Scans por dia (últimos 30 dias)
    daily = db.execute("""
        SELECT DATE(created_at) as dia, COUNT(*) as c
        FROM scans WHERE created_at >= DATE('now', '-30 days')
        GROUP BY dia ORDER BY dia
    """).fetchall()

    # Vulnerabilidades detectadas (do dashboard_stats)
    total_vulns = db.execute(
        "SELECT COALESCE(SUM(vuln_count), 0) as c FROM dashboard_stats"
    ).fetchone()["c"]

    # Tempo médio de scan
    avg_duration = db.execute(
        "SELECT COALESCE(AVG(duration_s), 0) as avg FROM dashboard_stats WHERE duration_s > 0"
    ).fetchone()["avg"]

    # Scans recentes
    recentes = db.execute("""
        SELECT scan_id, tool, dominio, status, inicio, fim
        FROM scans ORDER BY created_at DESC LIMIT 5
    """).fetchall()

    return jsonify({
        "total_scans": total,
        "rodando": rodando,
        "concluidos": concluidos,
        "erros": erros,
        "total_vulns": total_vulns,
        "avg_duration_s": round(avg_duration, 1),
        "top_tools": [{"tool": r["tool"], "count": r["c"]} for r in top_tools],
        "top_targets": [{"target": r["dominio"], "count": r["c"]} for r in top_targets],
        "daily": [{"date": r["dia"], "count": r["c"]} for r in daily],
        "recentes": [dict(r) for r in recentes],
    })


# ── Categorias de ferramentas ────────────────────────────────────────────

@app.route("/api/tools/categories")
def tools_categories():
    return jsonify(TOOLS_BY_CATEGORY)


# ---------------------------------------------------------------------------
# Frontend
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return send_from_directory("templates", "index.html")


@app.route("/static/<path:filename>")
def serve_static(filename: str):
    return send_from_directory("static", filename)


# ---------------------------------------------------------------------------
# Rate limiting (se flask-limiter disponível)
# ---------------------------------------------------------------------------

if limiter:
    limiter.limit("10 per minute")(scans_endpoint)
    limiter.limit("5 per minute")(batch_scan)
    limiter.limit("10 per minute")(run_osint)
    limiter.limit("3 per minute")(run_spiderfoot)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    port = int(os.getenv("PORT", "8080"))
    debug = os.getenv("FLASK_ENV") == "development"
    print(f"🛡️  SecuForge Toolkit — http://0.0.0.0:{port}")
    print(f"🔑 Auth: {'ATIVO' if AUTH_ENABLED else 'DESATIVADO'}")
    if AUTH_ENABLED:
        print(f"   API Key: {API_KEY}")
    print("⚠️  Use apenas contra alvos autorizados (art. 154-A CP).")
    app.run(host="0.0.0.0", port=port, debug=debug, threaded=True)
