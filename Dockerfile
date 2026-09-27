# ============================================================
# SecuForge Labs — Bug Bounty Toolkit
# Dockerfile com as 27 ferramentas de segurança
# Compatível com Docker e Podman (OCI-compliant)
#
# Build:
#   docker build -t bug-bounty-toolkit .
#   podman build -t bug-bounty-toolkit .
#
# ⚠️  Apenas contra alvos locais ou autorizados (art. 154-A CP)
# ============================================================

FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    RESULTADOS_DIR=/app/resultados \
    SECUFORGE_DB=/app/data/secuforge.db \
    SECUFORGE_KEY_FILE=/app/data/api.key

WORKDIR /app

# ── Base + Python ──
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip python3-venv \
    curl wget git unzip jq dnsutils whois \
    build-essential libssl-dev libffi-dev \
    ca-certificates gnupg lsb-release \
    && rm -rf /var/lib/apt/lists/*

# ── 1. Recon & Enumeração ──

# nmap
RUN apt-get update && apt-get install -y --no-install-recommends nmap && rm -rf /var/lib/apt/lists/*

# masscan
RUN apt-get update && apt-get install -y --no-install-recommends masscan && rm -rf /var/lib/apt/lists/*

# rustscan
RUN wget -q "https://github.com/RustScan/RustScan/releases/download/2.1.1/rustscan_2.1.1_amd64.deb" -O /tmp/rustscan.deb \
    && dpkg -i /tmp/rustscan.deb || true && apt-get install -f -y && rm /tmp/rustscan.deb

# subfinder
RUN wget -q "https://github.com/projectdiscovery/subfinder/releases/download/v2.6.6/subfinder_2.6.6_linux_amd64.zip" -O /tmp/subfinder.zip \
    && unzip -o /tmp/subfinder.zip -d /usr/local/bin/ subfinder && chmod +x /usr/local/bin/subfinder && rm /tmp/subfinder.zip

# httpx
RUN wget -q "https://github.com/projectdiscovery/httpx/releases/download/v1.6.8/httpx_1.6.8_linux_amd64.zip" -O /tmp/httpx.zip \
    && unzip -o /tmp/httpx.zip -d /usr/local/bin/ httpx && chmod +x /usr/local/bin/httpx && rm /tmp/httpx.zip

# amass
RUN wget -q "https://github.com/owasp-amass/amass/releases/download/v4.2.0/amass_Linux_amd64.zip" -O /tmp/amass.zip \
    && unzip -o /tmp/amass.zip -d /tmp/amass && mv /tmp/amass/amass_Linux_amd64/amass /usr/local/bin/ && chmod +x /usr/local/bin/amass && rm -rf /tmp/amass*

# ffuf
RUN wget -q "https://github.com/ffuf/ffuf/releases/download/v2.1.0/ffuf_2.1.0_linux_amd64.tar.gz" -O /tmp/ffuf.tar.gz \
    && tar -xzf /tmp/ffuf.tar.gz -C /usr/local/bin/ ffuf && chmod +x /usr/local/bin/ffuf && rm /tmp/ffuf.tar.gz

# gobuster
RUN wget -q "https://github.com/OJ/gobuster/releases/download/v3.6.0/gobuster_Linux_x86_64.tar.gz" -O /tmp/gobuster.tar.gz \
    && tar -xzf /tmp/gobuster.tar.gz -C /usr/local/bin/ gobuster && chmod +x /usr/local/bin/gobuster && rm /tmp/gobuster.tar.gz

# dirsearch
RUN pip3 install --break-system-packages dirsearch

# wfuzz
RUN pip3 install --break-system-packages wfuzz

# waybackurls
RUN wget -q "https://github.com/tomnomnom/waybackurls/releases/download/v0.1.0/waybackurls-linux-amd64-0.1.0.tgz" -O /tmp/waybackurls.tgz \
    && tar -xzf /tmp/waybackurls.tgz -C /usr/local/bin/ && chmod +x /usr/local/bin/waybackurls && rm /tmp/waybackurls.tgz

# gau
RUN wget -q "https://github.com/lc/gau/releases/download/v2.2.3/gau_2.2.3_linux_amd64.tar.gz" -O /tmp/gau.tar.gz \
    && tar -xzf /tmp/gau.tar.gz -C /usr/local/bin/ gau && chmod +x /usr/local/bin/gau && rm /tmp/gau.tar.gz

# dnsrecon
RUN pip3 install --break-system-packages dnsrecon

# fierce
RUN pip3 install --break-system-packages fierce

# ── 2. Vulnerability Scanning ──

# nuclei
RUN wget -q "https://github.com/projectdiscovery/nuclei/releases/download/v3.3.5/nuclei_3.3.5_linux_amd64.zip" -O /tmp/nuclei.zip \
    && unzip -o /tmp/nuclei.zip -d /usr/local/bin/ nuclei && chmod +x /usr/local/bin/nuclei && rm /tmp/nuclei.zip

# nikto
RUN apt-get update && apt-get install -y --no-install-recommends nikto && rm -rf /var/lib/apt/lists/*

# whatweb
RUN apt-get update && apt-get install -y --no-install-recommends whatweb && rm -rf /var/lib/apt/lists/*

# wpscan
RUN apt-get update && apt-get install -y --no-install-recommends ruby ruby-dev && \
    gem install wpscan --no-document && rm -rf /var/lib/apt/lists/*

# testssl.sh
RUN git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/testssl && \
    ln -s /opt/testssl/testssl.sh /usr/local/bin/testssl.sh

# sslscan
RUN apt-get update && apt-get install -y --no-install-recommends sslscan && rm -rf /var/lib/apt/lists/*

# ── 3. Exploit & Injection ──

# sqlmap
RUN pip3 install --break-system-packages sqlmap

# commix
RUN pip3 install --break-system-packages commix

# xsstrike
RUN pip3 install --break-system-packages xsstrike

# dalfox
RUN wget -q "https://github.com/hahwul/dalfox/releases/download/v2.9.3/dalfox_2.9.3_linux_amd64.tar.gz" -O /tmp/dalfox.tar.gz \
    && tar -xzf /tmp/dalfox.tar.gz -C /usr/local/bin/ dalfox && chmod +x /usr/local/bin/dalfox && rm /tmp/dalfox.tar.gz

# ── 4. Brute Force & Cracking ──

# hydra
RUN apt-get update && apt-get install -y --no-install-recommends hydra && rm -rf /var/lib/apt/lists/*

# john (jumbo)
RUN apt-get update && apt-get install -y --no-install-recommends john && rm -rf /var/lib/apt/lists/*

# hashcat
RUN apt-get update && apt-get install -y --no-install-recommends hashcat && rm -rf /var/lib/apt/lists/*

# ── 5. Network Analysis ──

# tshark
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends tshark && rm -rf /var/lib/apt/lists/*

# enum4linux
RUN apt-get update && apt-get install -y --no-install-recommends samba-common-bin ldap-utils && rm -rf /var/lib/apt/lists/* \
    && wget -q "https://raw.githubusercontent.com/CiscoCXSecurity/enum4linux/master/enum4linux.pl" -O /usr/local/bin/enum4linux \
    && chmod +x /usr/local/bin/enum4linux

# ── OSINT helpers ──
RUN pip3 install --break-system-packages theharvester

# ── Wordlists básicas ──
RUN mkdir -p /usr/share/wordlists && \
    wget -q "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt" \
         -O /usr/share/wordlists/common.txt && \
    wget -q "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/directory-list-2.3-small.txt" \
         -O /usr/share/wordlists/directory-list-small.txt && \
    wget -q "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt" \
         -O /usr/share/wordlists/subdomains-top5000.txt

# ── Dependências Python do toolkit ──
COPY requirements.txt /app/requirements.txt
RUN pip3 install --break-system-packages -r /app/requirements.txt

# ── Código do toolkit ──
COPY . /app/

RUN mkdir -p /app/resultados /app/data

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD curl -sf http://localhost:8080/api/health || exit 1

ENTRYPOINT ["python3", "api.py"]
