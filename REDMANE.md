A ordem depende do modo do scan (domínio/URL vs. IP), mais o que roda manual/sob demanda depois:

Pipeline automático (recon-full.sh, disparado por "Iniciar Scan")

┌──────────────┬──────────────────────────────────────────────────┬───────────────────────────────────────────────────────────┐
│    Passo     │                 Modo domínio/URL                 │                          Modo IP                          │
├──────────────┼──────────────────────────────────────────────────┼───────────────────────────────────────────────────────────┤
│ Dependências │ checa subfinder, httpx, gau, waybackurls, ffuf,  │ pula a checagem de subfinder/gau/waybackurls (não são     │
│              │ nuclei                                           │ chamados)                                                 │
├──────────────┼──────────────────────────────────────────────────┼───────────────────────────────────────────────────────────┤
│ 1/6          │ subfinder → subdominios/raw.txt                  │ pulado — só ecoa o próprio IP em raw.txt                  │
├──────────────┼──────────────────────────────────────────────────┼───────────────────────────────────────────────────────────┤
│ 1.5          │ —                                                │ nmap (varredura de portas) → alimenta o -ports do próximo │
│              │                                                  │  passo                                                    │
├──────────────┼──────────────────────────────────────────────────┼───────────────────────────────────────────────────────────┤
│ 2/6          │ httpx → hosts/ativos.txt (80/443)                │ httpx nas portas que o nmap achou                         │
├──────────────┼──────────────────────────────────────────────────┼───────────────────────────────────────────────────────────┤
│ 3/6          │ gau + waybackurls → params/                      │ pulado — arquivos vazios (web não indexa por IP)          │
├──────────────┼──────────────────────────────────────────────────┼───────────────────────────────────────────────────────────┤
│ 4/6          │ nuclei (pulado em --rapido)                      │ igual                                                     │
├──────────────┼──────────────────────────────────────────────────┼───────────────────────────────────────────────────────────┤
│ 5/6          │ ffuf (fuzzing)                                   │ igual                                                     │
├──────────────┼──────────────────────────────────────────────────┼───────────────────────────────────────────────────────────┤
│ 6/6          │ classificação (regex Python → achados)           │ igual                                                     │
├──────────────┼──────────────────────────────────────────────────┼───────────────────────────────────────────────────────────┤
│ final        │ report.py gera os relatórios                     │ igual                                                     │
└──────────────┴──────────────────────────────────────────────────┴───────────────────────────────────────────────────────────┘

Sob demanda, depois do scan concluído (não rodam sozinhos)
- 🛰️ Shodan — botão no card do scan, consulta os hosts de hosts/ativos.txt.
- 🔎 OSINT (theHarvester + amass + spiderfoot opcional) — botão no card do scan, compara com o subfinder.
- 🔓 John — bancada independente na página Ferramentas, sem depender de scan nenhum (você cola o hash).
- wifite — manual, só terminal (sudo wifite), fora do app inteiramente.

Ou seja: dentro do pipeline automático a ordem é sempre subfinder/nmap → httpx → gau/waybackurls → nuclei → ffuf → classificação → relatório; Shodan/OSINT/John ficam de fora de propósito, disparados por você depois, quando quiser.
