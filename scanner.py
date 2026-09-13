#!/usr/bin/env python3
"""
Scanner de site — dois modos, mesmo relatório:

  remoto : rastreia um domínio (httpx assíncrono, BFS, robots.txt)
  local  : importa arquivos .html/.htm de uma pasta e audita links relativos

Uso:
    pip install httpx beautifulsoup4

    # remoto
    python scanner.py https://exemplo.com --concurrency 20 --csv relatorio.csv
    # remoto, guardando o HTML de cada página
    python scanner.py https://exemplo.com --save-html ./paginas

    # local (pasta ou arquivo único)
    python scanner.py ./dist --csv relatorio.csv
    python scanner.py ./dist/index.html

Opcional (JS renderizado, só no modo remoto):
    pip install playwright && playwright install chromium
    python scanner.py https://exemplo.com --render
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import hashlib
import re
import sys
from dataclasses import dataclass, field, asdict
from pathlib import Path
from urllib.parse import urljoin, urldefrag, urlparse, unquote
from urllib.robotparser import RobotFileParser

import httpx
from bs4 import BeautifulSoup

USER_AGENT = "SiteScanner/3.0 (+uso interno)"
SECURITY_HEADERS = [
    "content-security-policy",
    "strict-transport-security",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
]
EXT_HTML = {".html", ".htm", ".xhtml"}


@dataclass
class PageResult:
    url: str
    status: int | None = None
    elapsed_ms: int = 0
    content_type: str = ""
    title: str = ""
    meta_description: str = ""
    h1_count: int = 0
    imgs_sem_alt: int = 0
    links_internos: int = 0
    links_externos: int = 0
    links_quebrados: str = ""
    missing_security_headers: str = ""
    arquivo_local: str = ""
    erro: str = ""
    origem: str = field(default="", repr=False)


def normalizar(url: str) -> str:
    url, _ = urldefrag(url)
    return url.rstrip("/") or url


def analisar_html(base: str, html: str) -> tuple[str, str, int, int, list[str]]:
    """Parsing puro (CPU-bound). `base` é a URL/URI usada para resolver hrefs relativos."""
    soup = BeautifulSoup(html, "html.parser")
    title = (soup.title.string or "").strip() if soup.title and soup.title.string else ""
    meta = soup.find("meta", attrs={"name": "description"})
    desc = (meta.get("content") or "").strip() if meta else ""
    h1 = len(soup.find_all("h1"))
    sem_alt = sum(1 for img in soup.find_all("img") if not img.get("alt"))

    hrefs: list[str] = []
    for a in soup.find_all("a", href=True):
        href = a["href"].strip()
        if not href or href.startswith(("mailto:", "tel:", "javascript:", "#", "data:")):
            continue
        hrefs.append(normalizar(urljoin(base, href)))
    return title, desc, h1, sem_alt, hrefs


# =====================================================================
# Modo remoto
# =====================================================================

class AsyncSiteScanner:
    def __init__(self, base_url: str, max_pages: int = 200, concurrency: int = 10,
                 delay: float = 0.0, timeout: float = 10.0, respect_robots: bool = True,
                 render: bool = False, save_html: str | None = None):
        self.base_url = normalizar(base_url)
        self.domain = urlparse(self.base_url).netloc
        self.max_pages = max_pages
        self.concurrency = concurrency
        self.delay = delay
        self.timeout = timeout
        self.respect_robots = respect_robots
        self.render = render
        self.save_dir = Path(save_html).resolve() if save_html else None

        self.sem = asyncio.Semaphore(concurrency)
        self.fila: asyncio.Queue[tuple[str, str]] = asyncio.Queue()
        self.visitados: set[str] = set()
        self.resultados: list[PageResult] = []
        self.robots: RobotFileParser | None = None
        self._browser = None
        self._pw = None

    # ---------- infraestrutura ----------

    async def _carregar_robots(self, client: httpx.AsyncClient) -> None:
        if not self.respect_robots:
            return
        rp = RobotFileParser()
        try:
            resp = await client.get(urljoin(self.base_url, "/robots.txt"))
            if resp.status_code == 200:
                rp.parse(resp.text.splitlines())
                self.robots = rp
        except httpx.HTTPError:
            pass

    def _permitido(self, url: str) -> bool:
        return self.robots.can_fetch(USER_AGENT, url) if self.robots else True

    def _mesmo_dominio(self, url: str) -> bool:
        return urlparse(url).netloc == self.domain

    def _agendar(self, url: str, origem: str) -> None:
        if (url in self.visitados
                or len(self.visitados) >= self.max_pages
                or not self._mesmo_dominio(url)
                or not self._permitido(url)):
            return
        self.visitados.add(url)
        self.fila.put_nowait((url, origem))

    def _caminho_salvo(self, url: str) -> Path:
        """Nome de arquivo estável e seguro derivado da URL."""
        p = urlparse(url)
        slug = re.sub(r"[^a-zA-Z0-9._-]+", "_", unquote(p.path).strip("/")) or "index"
        digest = hashlib.sha1(url.encode()).hexdigest()[:8]
        if not slug.endswith(tuple(EXT_HTML)):
            slug += ".html"
        return self.save_dir / f"{slug[:80]}__{digest}.html"

    # ---------- fetch ----------

    async def _fetch(self, client: httpx.AsyncClient, url: str) -> tuple[httpx.Response, str]:
        resp = await client.get(url)
        html = resp.text
        if self.render and "text/html" in resp.headers.get("content-type", ""):
            html = await self._render(url) or html
        return resp, html

    async def _render(self, url: str) -> str | None:
        if self._browser is None:
            return None
        page = await self._browser.new_page()
        try:
            await page.goto(url, wait_until="networkidle", timeout=self.timeout * 1000)
            return await page.content()
        except Exception:
            return None
        finally:
            await page.close()

    # ---------- workers ----------

    async def _worker(self, client: httpx.AsyncClient) -> None:
        while True:
            url, origem = await self.fila.get()
            try:
                async with self.sem:
                    await self._processar(client, url, origem)
                    if self.delay:
                        await asyncio.sleep(self.delay)
            finally:
                self.fila.task_done()

    async def _processar(self, client: httpx.AsyncClient, url: str, origem: str) -> None:
        try:
            resp, html = await self._fetch(client, url)
        except httpx.HTTPError as e:
            self.resultados.append(PageResult(url=url, erro=repr(e), origem=origem))
            print(f"[ERRO] {url} -> {e}", file=sys.stderr)
            return

        r = PageResult(
            url=url,
            origem=origem,
            status=resp.status_code,
            elapsed_ms=int(resp.elapsed.total_seconds() * 1000),
            content_type=resp.headers.get("content-type", "").split(";")[0],
        )
        presentes = {k.lower() for k in resp.headers}
        r.missing_security_headers = ", ".join(h for h in SECURITY_HEADERS if h not in presentes)

        if "text/html" in r.content_type:
            if self.save_dir:
                destino = self._caminho_salvo(url)
                await asyncio.to_thread(destino.write_text, html, "utf-8")
                r.arquivo_local = str(destino)

            title, desc, h1, sem_alt, hrefs = await asyncio.to_thread(analisar_html, url, html)
            r.title, r.meta_description, r.h1_count, r.imgs_sem_alt = title, desc, h1, sem_alt
            for href in hrefs:
                if self._mesmo_dominio(href):
                    r.links_internos += 1
                    self._agendar(href, url)
                else:
                    r.links_externos += 1

        self.resultados.append(r)
        print(f"[{r.status}] {r.elapsed_ms:>5}ms  {url}")

    # ---------- execução ----------

    async def scan(self) -> list[PageResult]:
        if self.save_dir:
            self.save_dir.mkdir(parents=True, exist_ok=True)

        limits = httpx.Limits(max_connections=self.concurrency,
                              max_keepalive_connections=self.concurrency)
        async with httpx.AsyncClient(
            headers={"User-Agent": USER_AGENT},
            timeout=self.timeout,
            follow_redirects=True,
            limits=limits,
        ) as client:
            await self._carregar_robots(client)
            if self.render:
                await self._abrir_browser()

            self._agendar(self.base_url, "")
            workers = [asyncio.create_task(self._worker(client)) for _ in range(self.concurrency)]
            try:
                await self.fila.join()
            finally:
                for w in workers:
                    w.cancel()
                await asyncio.gather(*workers, return_exceptions=True)
                await self._fechar_browser()

        return self.resultados

    async def _abrir_browser(self) -> None:
        try:
            from playwright.async_api import async_playwright
        except ImportError:
            print("Playwright não instalado — seguindo sem renderização.", file=sys.stderr)
            self.render = False
            return
        self._pw = await async_playwright().start()
        self._browser = await self._pw.chromium.launch()

    async def _fechar_browser(self) -> None:
        if self._browser:
            await self._browser.close()
            await self._pw.stop()
            self._browser = None


# =====================================================================
# Modo local — importa arquivos HTML já existentes
# =====================================================================

class LocalHtmlScanner:
    def __init__(self, caminho: str, max_pages: int = 5000):
        self.raiz = Path(caminho).resolve()
        self.max_pages = max_pages
        self.resultados: list[PageResult] = []
        self.referenciados: set[Path] = set()

    def _arquivos(self) -> list[Path]:
        if self.raiz.is_file():
            return [self.raiz]
        arquivos = sorted(p for p in self.raiz.rglob("*")
                          if p.is_file() and p.suffix.lower() in EXT_HTML)
        return arquivos[:self.max_pages]

    def _rotulo(self, p: Path) -> str:
        base = self.raiz.parent if self.raiz.is_file() else self.raiz
        try:
            return str(p.relative_to(base))
        except ValueError:
            return str(p)

    def scan(self) -> list[PageResult]:
        for arquivo in self._arquivos():
            r = PageResult(url=self._rotulo(arquivo), content_type="text/html",
                           arquivo_local=str(arquivo), status=200)
            try:
                html = arquivo.read_text(encoding="utf-8", errors="replace")
            except OSError as e:
                r.status = None
                r.erro = repr(e)
                self.resultados.append(r)
                continue

            title, desc, h1, sem_alt, hrefs = analisar_html(arquivo.as_uri(), html)
            r.title, r.meta_description, r.h1_count, r.imgs_sem_alt = title, desc, h1, sem_alt

            quebrados: list[str] = []
            for href in hrefs:
                if href.startswith("file://"):
                    r.links_internos += 1
                    alvo = Path(unquote(urlparse(href).path))
                    if alvo.is_dir():
                        alvo = alvo / "index.html"
                    if alvo.exists():
                        self.referenciados.add(alvo.resolve())
                    else:
                        quebrados.append(self._rotulo(alvo))
                else:
                    r.links_externos += 1
            r.links_quebrados = ", ".join(quebrados)
            self.resultados.append(r)
            marca = "OK " if not quebrados else f"{len(quebrados)} link(s) quebrado(s)"
            print(f"[{marca}] {r.url}")
        return self.resultados

    def orfas(self) -> list[PageResult]:
        """Páginas que nenhum outro arquivo referencia (exceto a raiz/index)."""
        entradas = {"index.html", "index.htm"}
        return [r for r in self.resultados
                if Path(r.arquivo_local).resolve() not in self.referenciados
                and Path(r.arquivo_local).name.lower() not in entradas]


# =====================================================================
# Relatório
# =====================================================================

def resumo(resultados: list[PageResult], orfas: list[PageResult] | None = None) -> str:
    quebrados = [r for r in resultados if r.erro or (r.status and r.status >= 400)]
    com_links_quebrados = [r for r in resultados if r.links_quebrados]
    sem_titulo = [r for r in resultados if not r.title and not r.erro]
    sem_desc = [r for r in resultados if not r.meta_description and not r.erro]
    sem_alt = sum(r.imgs_sem_alt for r in resultados)

    linhas = [
        f"\nPáginas analisadas: {len(resultados)}",
        f"Com erro / status >= 400: {len(quebrados)}",
        f"Páginas com links quebrados: {len(com_links_quebrados)}",
        f"Sem <title>: {len(sem_titulo)}   |   sem meta description: {len(sem_desc)}",
        f"Imagens sem alt: {sem_alt}",
    ]
    if quebrados:
        linhas.append("\nFalhas de acesso:")
        linhas += [f"  {r.status or 'ERR'} {r.url}  (origem: {r.origem or '-'})" for r in quebrados]
    if com_links_quebrados:
        linhas.append("\nLinks apontando para arquivos inexistentes:")
        linhas += [f"  {r.url} -> {r.links_quebrados}" for r in com_links_quebrados]
    if orfas:
        linhas.append("\nPáginas órfãs (ninguém aponta para elas):")
        linhas += [f"  {r.url}" for r in orfas]

    lentas = sorted((r for r in resultados if r.elapsed_ms), key=lambda r: r.elapsed_ms, reverse=True)[:5]
    if lentas:
        linhas.append("\nMais lentas:")
        linhas += [f"  {r.elapsed_ms:>6}ms  {r.url}" for r in lentas]
    return "\n".join(linhas)


def exportar_csv(resultados: list[PageResult], caminho: str) -> None:
    campos = list(asdict(PageResult(url="")).keys())
    with open(caminho, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=campos)
        writer.writeheader()
        for r in resultados:
            writer.writerow(asdict(r))


def main() -> None:
    p = argparse.ArgumentParser(description="Scanner de site (remoto ou pasta HTML local)")
    p.add_argument("alvo", help="URL do site ou caminho de uma pasta/arquivo HTML")
    p.add_argument("--max-pages", type=int, default=200)
    p.add_argument("--concurrency", type=int, default=10)
    p.add_argument("--delay", type=float, default=0.0)
    p.add_argument("--timeout", type=float, default=10.0)
    p.add_argument("--ignore-robots", action="store_true")
    p.add_argument("--render", action="store_true", help="renderiza JS com Playwright (modo remoto)")
    p.add_argument("--save-html", metavar="DIR", help="salva o HTML de cada página (modo remoto)")
    p.add_argument("--csv")
    args = p.parse_args()

    caminho = Path(args.alvo)
    if caminho.exists():
        scanner = LocalHtmlScanner(args.alvo, max_pages=args.max_pages)
        resultados = scanner.scan()
        print(resumo(resultados, scanner.orfas()))
    else:
        remoto = AsyncSiteScanner(
            args.alvo,
            max_pages=args.max_pages,
            concurrency=args.concurrency,
            delay=args.delay,
            timeout=args.timeout,
            respect_robots=not args.ignore_robots,
            render=args.render,
            save_html=args.save_html,
        )
        resultados = asyncio.run(remoto.scan())
        print(resumo(resultados))

    if args.csv:
        exportar_csv(resultados, args.csv)
        print(f"\nCSV salvo em {args.csv}")


if __name__ == "__main__":
    main()
