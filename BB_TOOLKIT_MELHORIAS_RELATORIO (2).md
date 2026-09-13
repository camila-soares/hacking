# BB Toolkit — Melhorias para Relatórios, Findings e Apresentação Comercial

## Objetivo

Evoluir o BB Toolkit de uma ferramenta de reconhecimento técnico para uma plataforma de **External Attack Surface Assessment**, com fluxo claro de validação, gestão de evidências, classificação de risco, relatórios executivos e relatórios técnicos.

A principal mudança conceitual é separar:

- descoberta automatizada;
- potencial vulnerabilidade;
- vulnerabilidade confirmada;
- falso positivo;
- observação informacional.

O cliente não deve receber resultados brutos de scanner como se fossem vulnerabilidades confirmadas.

---

# 1. Novo modelo de classificação dos findings

## Problema atual

O relatório apresenta contadores como:

- Crítico;
- Alto;
- Médio;
- Baixo.

Entretanto, alguns achados são apenas inferidos a partir de parâmetros, URLs ou heurísticas.

Exemplo:

```text
Open Redirect
Parâmetro: redirect_to
Severidade: Médio
```

A existência de um parâmetro chamado `redirect_to` não confirma por si só uma vulnerabilidade.

## Mudança proposta

Adicionar um campo de status obrigatório para cada finding:

```text
POTENTIAL
CONFIRMED
FALSE_POSITIVE
INFORMATIONAL
```

### POTENTIAL

Achado identificado automaticamente que ainda necessita de validação manual.

### CONFIRMED

Vulnerabilidade reproduzida e validada manualmente.

### FALSE_POSITIVE

Resultado automatizado que, após análise, não representa uma vulnerabilidade.

### INFORMATIONAL

Informação útil sobre a superfície de ataque, mas sem vulnerabilidade associada.

---

# 2. Alterar os indicadores do dashboard

## Situação atual

Exemplo:

```text
19 Subdomínios
14 Hosts Ativos
109 URLs c/ Params
1 Crítico
0 Altos
2 Médios
```

## Modelo recomendado

```text
19
Ativos descobertos

14
Ativos responsivos

109
URLs analisadas

3
Candidatos à validação

0
Críticos confirmados

0
Altos confirmados

0
Médios confirmados
```

Os contadores de severidade devem considerar apenas findings com:

```text
status = CONFIRMED
```

---

# 3. Separar superfície de ataque de vulnerabilidades

Criar seções independentes.

## Attack Surface

Deve incluir:

- domínios;
- subdomínios;
- IPs;
- hosts responsivos;
- portas;
- tecnologias;
- serviços;
- URLs;
- parâmetros;
- endpoints;
- certificados;
- DNS;
- recursos públicos encontrados.

## Findings

Deve conter apenas achados de segurança classificados.

Exemplo:

```text
Findings
├── Confirmados
├── Potenciais
├── Informacionais
└── Falsos positivos
```

---

# 4. Renomear "Arquivos Sensíveis"

## Problema

Itens como:

```text
sitemap.xml
feed.xml
assetlinks.json
gpc.json
```

não são necessariamente arquivos sensíveis.

## Novo nome

Usar:

```text
Arquivos e Recursos Descobertos
```

E adicionar classificação:

```text
PUBLIC
INFORMATIONAL
REVIEW
EXPOSED
SENSITIVE
```

## Exemplos

### PUBLIC

```text
sitemap.xml
robots.txt
feed.xml
assetlinks.json
```

### REVIEW

```text
config.json
manifest.json
debug endpoint
```

### SENSITIVE

Somente quando realmente exposto:

```text
.env
.git/
backup.sql
database.sql
config.php.bak
id_rsa
credentials.json
```

---

# 5. Novo formato para cada finding

Cada finding deve possuir uma página ou painel detalhado.

## Campos obrigatórios

```text
Título
Status
Severidade
Confiança
CVSS
Vetor CVSS
CWE
OWASP Category
Ativo afetado
Endpoint
Parâmetro
Descrição
Impacto técnico
Impacto de negócio
Evidência
Passos de reprodução
Recomendação
Referências
Data da descoberta
Data da validação
Analista
Status de remediação
```

---

# 6. Exemplo de finding melhorado

## Open Redirect

### Status

```text
POTENTIAL
```

### Severidade

```text
MEDIUM
```

### Confiança

```text
65%
```

### Ativo

```text
https://example.com
```

### Endpoint

```text
/auth/protected-redirect/external
```

### Parâmetro

```text
location
```

### Descrição

Foi identificado um parâmetro utilizado para redirecionamento de usuários.

O comportamento necessita de validação manual para determinar se destinos externos arbitrários são permitidos.

### Impacto potencial

Caso confirmado, um atacante pode utilizar uma URL pertencente ao domínio legítimo para redirecionar usuários a páginas externas controladas por terceiros.

Isso pode aumentar a efetividade de campanhas de engenharia social e phishing.

### Recomendação

Implementar uma allowlist de destinos permitidos e evitar aceitar URLs absolutas fornecidas diretamente pelo usuário.

### CWE

```text
CWE-601
```

---

# 7. Workflow de validação manual

Adicionar ações no finding:

```text
[ Confirmar vulnerabilidade ]

[ Marcar como falso positivo ]

[ Necessita validação ]

[ Marcar como informacional ]
```

## Fluxo

```text
Recon automatizado
       ↓
Potential Finding
       ↓
Validação manual
       ↓
┌───────────────┬────────────────┬─────────────────┐
│ CONFIRMED     │ FALSE_POSITIVE │ INFORMATIONAL   │
└───────────────┴────────────────┴─────────────────┘
       ↓
Relatório final
```

---

# 8. Evidências

Cada finding confirmado deve possuir evidências associadas.

## Tipos

```text
HTTP Request
HTTP Response
Screenshot
Arquivo
Comando executado
Log
Timestamp
Hash da evidência
```

## Exemplo

```text
Evidence ID: EVT-2026-00031

Request:
GET /redirect?url=https://example.org HTTP/1.1

Response:
HTTP/1.1 302 Found
Location: https://example.org

Timestamp:
2026-09-13T11:42:17-03:00

SHA-256:
...
```

Adicionar botão:

```text
📎 Ver Evidências
```

---

# 9. Resumo executivo

Antes do conteúdo técnico, criar uma seção específica para gestão.

## Exemplo

```text
EXTERNAL ATTACK SURFACE ASSESSMENT

Cliente:
Empresa XYZ

Escopo:
example.com

Data:
13/09/2026

Tipo:
Reconhecimento externo autorizado

Risco Geral:
MODERADO
```

## Texto exemplo

> A avaliação identificou 19 ativos associados ao escopo, dos quais 14 responderam externamente. Foram analisadas 109 URLs contendo parâmetros e encontrados 3 pontos que requerem validação manual. Até o momento, nenhuma vulnerabilidade crítica ou alta foi confirmada.

---

# 10. Estrutura do relatório para cliente

```text
1. Resumo Executivo

2. Escopo

3. Metodologia

4. Superfície de Ataque

5. Vulnerabilidades Confirmadas

6. Potenciais Vulnerabilidades

7. Observações Informacionais

8. Plano de Remediação

9. Priorização

10. Metodologia de Reteste

11. Apêndice Técnico
```

---

# 11. Relatório Executivo e Relatório Técnico

Criar dois tipos de exportação.

## Executive Report

Destinado a:

- diretoria;
- gestão;
- CISO;
- gestores;
- responsáveis pelo negócio.

Conteúdo:

```text
Resumo executivo
Risco geral
Principais exposições
Vulnerabilidades confirmadas
Impactos de negócio
Prioridades
Plano de ação
```

Tamanho sugerido:

```text
5 a 10 páginas
```

---

## Technical Report

Destinado a:

- Segurança;
- DevSecOps;
- desenvolvimento;
- infraestrutura;
- SRE.

Conteúdo:

```text
Todos os findings
Requests
Responses
Screenshots
CVSS
CWE
Endpoints
Evidências
Passos de reprodução
Recomendações
Referências
```

---

# 12. Botão de exportação

Adicionar:

```text
⬇ Exportar Relatório
```

Opções:

```text
Executive Report — PDF

Technical Report — PDF

Technical Report — HTML

Findings — CSV

Findings — JSON
```

---

# 13. Melhorar o histórico de scans

Exemplo de card:

```text
13/09/2026 11:45

Target
example.com

Status
CONCLUÍDO

19 ativos
14 responsivos
3 potenciais findings
0 confirmados

[Visualizar]
[Comparar]
[Exportar]
```

---

# 14. Comparação entre scans

Adicionar:

```text
Comparar com scan anterior
```

Exemplo:

| Indicador | Scan anterior | Scan atual | Diferença |
|---|---:|---:|---:|
| Ativos | 17 | 19 | +2 |
| Hosts ativos | 13 | 14 | +1 |
| URLs | 94 | 109 | +15 |
| Críticos confirmados | 0 | 0 | 0 |
| Altos confirmados | 0 | 0 | 0 |
| Médios confirmados | 1 | 2 | +1 |

---

# 15. Detecção de mudanças

Criar eventos:

```text
NEW_ASSET
REMOVED_ASSET
NEW_PORT
CLOSED_PORT
NEW_SERVICE
TECHNOLOGY_CHANGED
NEW_FINDING
FINDING_FIXED
FINDING_REOPENED
CERTIFICATE_CHANGED
DNS_CHANGED
```

Isso permite evoluir a aplicação para:

```text
Continuous Attack Surface Monitoring
```

---

# 16. Risco geral

Criar um cálculo separado para:

```text
CRITICAL
HIGH
MODERATE
LOW
INFORMATIONAL
```

O cálculo deve usar somente findings confirmados.

Possível regra inicial:

```text
Critical confirmado → CRITICAL

High confirmado → HIGH

Medium confirmado → MODERATE

Somente Low → LOW

Nenhum finding confirmado → INFORMATIONAL
```

---

# 17. CVSS

Adicionar suporte a:

```text
CVSS 4.0
```

Salvar:

```text
score
severity
vector
```

Exemplo:

```text
CVSS Score:
6.1

Vector:
CVSS:4.0/...
```

Nunca armazenar somente:

```text
"Medium"
```

A severidade deve ser derivada do score quando aplicável.

---

# 18. Impacto técnico x impacto de negócio

Separar:

## Impacto técnico

Exemplo:

```text
Redirecionamento arbitrário para domínio externo.
```

## Impacto de negócio

Exemplo:

```text
A vulnerabilidade pode aumentar a credibilidade de campanhas de engenharia social ao utilizar um domínio pertencente à organização como ponto inicial de navegação.
```

Essa distinção aumenta muito a qualidade do relatório comercial.

---

# 19. Metodologia

Criar seção contendo:

```text
Reconhecimento passivo
Reconhecimento ativo autorizado
Enumeração DNS
Descoberta de subdomínios
Fingerprinting HTTP
Descoberta de endpoints
Análise de parâmetros
Scanners automatizados
Validação manual
Classificação de risco
```

Também registrar:

```text
Ferramentas utilizadas
Versões
Data da execução
Configuração
Limitações
```

---

# 20. Limitações

Adicionar seção explícita:

```text
Este assessment representa uma fotografia do ambiente no período analisado.

Resultados automatizados podem produzir falsos positivos.

Potenciais vulnerabilidades devem passar por validação manual antes de serem classificadas como vulnerabilidades confirmadas.
```

---

# 21. Escopo e autorização

Adicionar ao relatório:

```text
Escopo autorizado
Domínios
Subdomínios
IPs
Período
Técnicas permitidas
Técnicas proibidas
Limites de requisição
Responsável pela autorização
Referência da autorização
```

Não executar testes fora desse escopo.

---

# 22. Dashboard principal

Sugestão de menu:

```text
Dashboard

Targets

Scans

Attack Surface

Findings

Evidence

Reports

Monitoring

Settings
```

---

# 23. Dashboard de findings

Filtros:

```text
Status

Severidade

Target

Ativo

CWE

OWASP

Data

Analista
```

Exemplo:

```text
[CONFIRMED] [HIGH]

Broken Access Control

api.example.com

CWE-862

Validado em:
13/09/2026
```

---

# 24. Remediação

Adicionar ciclo:

```text
OPEN
IN_PROGRESS
READY_FOR_RETEST
FIXED
ACCEPTED_RISK
WONT_FIX
```

Fluxo:

```text
Finding confirmado
       ↓
OPEN
       ↓
IN_PROGRESS
       ↓
READY_FOR_RETEST
       ↓
Reteste
       ↓
FIXED
```

---

# 25. Reteste

Cada finding deve permitir:

```text
Solicitar reteste
```

Registrar:

```text
Data
Responsável
Resultado
Evidência
Observação
```

Resultado:

```text
FIXED
PARTIALLY_FIXED
NOT_FIXED
```

---

# 26. Roadmap sugerido

## Fase 1 — Qualidade dos findings

Prioridade máxima.

Implementar:

```text
POTENTIAL
CONFIRMED
FALSE_POSITIVE
INFORMATIONAL
```

Adicionar:

```text
evidências
validação manual
CVSS
CWE
impacto
recomendação
```

---

## Fase 2 — Relatórios profissionais

Implementar:

```text
Executive Summary
Executive PDF
Technical PDF
Exportação JSON
Exportação CSV
```

---

## Fase 3 — Histórico e comparação

Implementar:

```text
Scan history
Diff entre scans
Novos ativos
Ativos removidos
Novos findings
Findings corrigidos
```

---

## Fase 4 — Remediação

Implementar:

```text
workflow de correção
reteste
status
responsável
SLA
```

---

## Fase 5 — Continuous Monitoring

Implementar:

```text
Scans agendados

Asset monitoring

Certificate monitoring

DNS monitoring

Exposure monitoring

Alertas
```

---

# 27. Posicionamento comercial

Não vender:

```text
"Uma ferramenta que roda Subfinder, FFUF e Nuclei."
```

Posicionar como:

```text
External Attack Surface & Security Assessment Platform
```

O valor entregue é:

```text
Descoberta
       ↓
Validação
       ↓
Priorização
       ↓
Evidência
       ↓
Remediação
       ↓
Reteste
       ↓
Monitoramento contínuo
```

---

# 28. Serviços que podem utilizar a plataforma

## Attack Surface Assessment

Entrega:

```text
inventário externo
ativos expostos
tecnologias
serviços
potenciais riscos
relatório executivo
```

---

## Web/API Security Assessment

Entrega:

```text
validação manual
OWASP
autenticação
autorização
sessão
APIs
CVSS
evidências
recomendações
```

---

## Continuous Exposure Monitoring

Entrega:

```text
scans recorrentes
novos ativos
novos serviços
mudanças DNS
novos findings
alertas
relatórios periódicos
```

---

# 29. Arquitetura funcional desejada

```text
Target
   ↓
Recon
   ↓
Asset Discovery
   ↓
Automated Analysis
   ↓
Potential Findings
   ↓
Manual Validation
   ↓
Confirmed Findings
   ↓
Risk Scoring
   ↓
Evidence
   ↓
Executive Report
   ↓
Technical Report
   ↓
Remediation
   ↓
Retest
   ↓
Continuous Monitoring
```

---

# 30. Prioridade imediata

As três mudanças mais importantes são:

## 1. Status dos findings

Implementar:

```text
POTENTIAL
CONFIRMED
FALSE_POSITIVE
INFORMATIONAL
```

## 2. Relatório executivo

Adicionar:

```text
Resumo Executivo
Risco geral
Impacto de negócio
Prioridades
Plano de ação
```

## 3. Exportação

Criar:

```text
Executive Report PDF
Technical Report PDF
```

Essas três mudanças já alteram significativamente a percepção da ferramenta e aproximam o BB Toolkit de uma solução comercial de assessment e gestão de superfície de ataque.
