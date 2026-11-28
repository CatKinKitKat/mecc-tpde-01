# TPDE - Grupo 12 - Recon Passiva

## Ficha de Reconhecimento Passivo - Camara Municipal de Sines

> TLDR: recon passivo executado, sem scan ativo.

Alvo: Camara Municipal de Sines (Moodle, 16 Nov 2026).
Dominio confirmado: `sines.pt`. O palpite inicial `cm-sines.pt` estava errado e foi descartado.
Executado: whois, dig, subfinder, theHarvester, curl, dorks Google/DDG, leitura de PDFs publicos.
Nao executado: dirbuster/gobuster, Nmap, Nessus, Nikto, bruteforce, ataques.
Merge com o Gelson: comparar outputs e consolidar no relatorio LaTeX.

### 1. Identificacao da Organizacao e Presenca Fisica

#### a) Sede e filiais: localizacao exata e mapeamento de instalacoes

> `whois sines.pt`
> `dig +short sines.pt A`
> `curl -s https://www.gov.pt/entidades/camara-municipal-de-sines`

Queries:
- `Camara Municipal de Sines site oficial dominio`
- `"Camara Municipal de Sines" morada contactos`
- `site:gov.pt "Camara Municipal de Sines"`

Info encontrada:
- Sede: Largo Ramos da Costa, 7520-159 Sines; coords 37.954653,-8.864333; tel 269 630 600; info@mun-sines.pt [3].
- Portal oficial: www.sines.pt [1].
- Balcao: Espaco Cidadao de Porto Covo, Rua do Mar n.4, 7520-437 Porto Covo [3].
- WHOIS: `Domain: sines.pt`, admin Municipio de Sines, Largo Ramos Costa, 7520-159 Sines, PT; criado 1988-06-30, alterado 2023-08-02, `ACTIVE`.
- NIPC 502 563 010 e morada Largo Ramos da Costa 21 A constam em PDF publico [7].

#### b) Seguranca fisica: perimetros, camaras e controlos de acesso

> Sem comando local; observacao visual a fazer manualmente no Google Maps.

Queries:
- `"Camara Municipal de Sines" camaras seguranca acesso`
- `site:sines.pt "camaras" OR "vigilancia" OR "seguranca"`

Info encontrada:
- Sem observacao visual verificada de camaras ou perimetros; usar as coordenadas acima.
- Achado publico: concurso para "Servico de vigilancia, assistencia balnear, patrulhamento e coordenacao de nadadores salvadores - Epoca Balnear 2024" [16].
- Area de "Contratacao" do municipio publica avisos e concursos [15].

### 2. Pegada Logica e de Infraestrutura (Footprinting)

#### a) Propriedades de dominio: WHOIS, subdominios e historico DNS

> `whois sines.pt`
> `dig sines.pt ANY +noall +answer`
> `subfinder -d sines.pt -silent -o recon/subfinder.txt`
> `curl -s "https://crt.sh/?q=%.sines.pt&output=json"` -> 200, 16 registos

Queries:
- `site:crt.sh "sines.pt"`
- `"sines.pt" -site:sines.pt`

Info encontrada:
- WHOIS: registo `ACTIVE`, criado 1988-06-30, alterado 2023-08-02; admin Municipio de Sines, Largo Ramos Costa, 7520-159 Sines, PT.
- Nameserver no WHOIS: A.DNS.PT, B.DNS.PT, C.DNS.PT, D.DNS.PT, E.DNS.PT, G.DNS.PT, H.DNS.PT, NS.DNS.BR, NS2.NIC.FR.
- NS autoritativos observados por `dig`: dns4.cloudns.net, dns3.cloudns.net, dns8.cloudns.net, dns7.cloudns.net (divergencia face ao WHOIS).
- TXT: `_globalsign-domain-verification=...` (token publico de verificacao).
- `subfinder`: 17 subdominios, entre eles www, servicosonline, biblioteca, arquivo, centrodeartes, informa, nautical, tasquinhas, sig.
- crt.sh: 16 registos, 3 nomes unicos: `*.sines.pt`, `sines.pt`, `informa.sines.pt` [13].

#### b) Enderecamento IP: netblocks, ASN e topologia externa

> `dig +short sines.pt A`
> `whois 195.23.140.168`
> `curl -s "https://stat.ripe.net/data/prefix-overview/data.json?resource=195.23.140.168"` -> `data: null`

Queries:
- `site:bgp.he.net "sines.pt"`
- `site:ripe.net "sines.pt"`

Info encontrada:
- A: `195.23.140.168`.
- WHOIS do IP: `195.23.140.0/24`, netname `NOS`, descr `NOS COMUNICACOES S.A.`, country PT, org `ORG-TPS1-RIPE`, mnt-by `AS2860-MNT`, abuse `abuse@nos.pt`.
- RIPEstat network-info: prefixo `195.23.0.0/16`, ASN nao devolvido [15]; WHOIS IP mostra `mnt-by AS2860-MNT` (ASN 2860 por confirmar).

#### c) Servicos externos: cloud, VPN, Citrix, e-mail, favicon e tecnologias

> `dig sines.pt MX` -> sem registos MX
> `theHarvester -d sines.pt -b duckduckgo -l 50` -> 0 IPs, 0 emails, 0 pessoas, 0 hosts

Queries:
- `site:sines.pt "servicosonline" OR "balcao" OR "autenticacao"`
- `"Municipio de Sines" VPN OR Citrix OR Office365`
- `site:sines.pt "vpn" OR "citrix" OR "office365" OR "webmail"`

Info encontrada:
- Portal de servicos online em `servicosonline.sines.pt` [18], tambem linkado na pagina "Servicos Online" do site oficial [17].
- Sem MX publico observado; o TXT Globalsign e o unico sinal de verificacao de dominio visto.
- Sem resultados de AnyConnect, Citrix, Office365 ou favicon hash nesta execucao.
- `theHarvester` DuckDuckGo nao encontrou IPs, emails, pessoas ou hosts.

### 3. Analise de Metadados e Ficheiros Expostos

#### a) Metadados de documentos publicos (PDF, DOCX, XLSX)

> `curl -sL -o recon/<ficheiro>.pdf <url>`
> `python3 -c "from pypdf import PdfReader; r=PdfReader('<ficheiro>'); print(r.pages.__getitem__(0).extract_text())"`
> `exiftool` disponivel, nao corrido sobre o conjunto todo

Queries:
- `site:sines.pt filetype:pdf`
- `site:sines.pt "@mun-sines.pt" OR "@sines.pt"`

Info encontrada:
- PDF de conselheiro: Helder Alexandre Gil Guerreiro, conselheiro, mandato 2017/2021, CDU; contacto `geral@mun-sines.pt`, +351 269 630 600, fax 269 633 022, NIPC 502 563 010 [7].
- PDF "Grandes Opcoes do Plano e Orcamento 2025-2029", 220 paginas [12].
- PDF "Relatorio Anual de Avaliacao ... 2010", 25 paginas, riscos de corrupcao [10].
- Dork `filetype:pdf` tambem devolveu boletins "Sines em Agenda", "SINEENSE" e "Sines Municipal".

#### b) Fugas de credenciais ou dados em repositorios de terceiros

> Sem API key HIBP; nao consultado por dominio.

Queries:
- `site:github.com "sines.pt"`
- `site:pastebin.com "mun-sines.pt"`
- `"@mun-sines.pt" "password" OR "senha"`

Info encontrada:
- Sem resultados relevantes nos dorks acima.
- Pastebin devolveu apenas paginas genericas, sem paste especifico do municipio.

#### c) Historico web: paginas e ficheiros removidos

> `curl -s "http://web.archive.org/cdx/search/cdx?url=sines.pt/*&output=json&filter=statuscode:200&fl=timestamp,original&collapse=digest&limit=20"` -> 200

Queries:
- `site:web.archive.org "sines.pt"`

Info encontrada:
- Wayback CDX: 20 snapshots entre 2007-03-28 e 2016-06-25, urls `sines.pt` e `www.sines.pt` [14]; limite de 20 usado, existem mais.

#### d) Enumeracao muito leve de diretorios (opcional)

> NAO EXECUTADO nesta fase. Limites se for feito manualmente: wordlist curta, 1-2 threads, sem recursao, sem login, sem payloads, sem exploits.
> `gobuster dir -u https://www.sines.pt -w /usr/share/wordlists/dirb/common.txt -t 2 -q -o recon/gobuster.txt`
> `dirb https://www.sines.pt/ /usr/share/dirb/wordlists/small.txt -o recon/dirb.txt`
> Alternativa passiva: `site:sines.pt inurl:/admin/ OR inurl:/backup/ OR inurl:/uploads/`

Info encontrada:
- Nao executado; sem dados.

### 4. Inteligencia sobre Colaboradores

#### a) Estrutura organizacional, cargos e departamentos

Queries:
- `site:linkedin.com/in "Camara Municipal de Sines"`
- `site:linkedin.com/company "Municipio de Sines"`

Info encontrada:
- Despacho de 2025 revela divisoes: Gabinete de Apoio a Presidencia e Vereacao, Divisao de Administracao e Financas, Divisao Juridica, Divisao de Obras Municipais, Sistemas e Tecnologias de Informacao, Unidade de Atendimento e Gestao Documental [8].
- Nomes em TI: Elisabete Maria Rego Vera Ruivo, Goncalo Jose Gamito Pereira, Nadia da Conceicao Viegas da Silva, Ricardo Victor da Silva [8].
- Conselheiro Helder Guerreiro, CDU, sem delegacoes [7].
- gov.pt descreve areas: saude, educacao, acao social, ambiente, transportes, comunicacoes, abastecimento, desporto, cultura, defesa do consumidor, protecao civil [3].
- Resultados LinkedIn nao foram confirmados como funcionarios; nao usar sem validacao.

#### b) Formato do e-mail institucional

> `theHarvester -d sines.pt -b duckduckgo -l 50` -> 0 emails

Queries:
- `"@mun-sines.pt"`
- `site:sines.pt "@"`

Info encontrada:
- Dominio de correio observado: `@mun-sines.pt`, nao `@sines.pt` [3][7].
- Enderecos publicos: `info@mun-sines.pt` [3], `geral@mun-sines.pt` [7].
- theHarvester nao encontrou emails adicionais.

#### c) Exposicao de e-mails corporativos em bases de fuga

Queries:
- `"@mun-sines.pt" site:haveibeenpwned.com`
- `"@mun-sines.pt" "breach" OR "vazamento"`

Info encontrada:
- Sem resultado especifico nesta execucao.

### 5. Informacao de Negocio e Relacionamentos

#### a) Parceiros e fornecedores com acesso a infraestrutura

Queries:
- `site:base.gov.pt "Camara Municipal de Sines" contrato`
- `site:sines.pt "ajuste direto" OR "contrato"`

Info encontrada:
- Painel "Contratacao" no site oficial [15].
- Concurso publico de vigilancia/balnear 2024 [16].
- Portal Autarquico tem seccoes "Cooperacao Tecnica e Financeira" e "Protocolos / Parcerias" [5].
- Base.gov: dork encontrou contratos, mas os PDFs tentados devolveram 404; nao usar como evidencia.

#### b) Dados financeiros, aquisicoes e tecnologias criticas

> `curl -sL -o recon/gop_2025_2029.pdf https://www.sines.pt/cmsines/uploads/document/file/12287/grandes_opcoes_do_plano_e_orcamento_2025_2029.pdf`

Queries:
- `site:sines.pt "relatorio anual" OR "orcamento"`

Info encontrada:
- Pagina "Opcoes do Plano / Orcamento" [6].
- GOP 2025-2029, 220 paginas [12].
- Relatorio Anual de Avaliacao 2010, 25 paginas [10].

### 6. Modelacao de Ameacas

- Ativos criticos: `sines.pt`, `servicosonline.sines.pt` [18], portal gov.pt [3].
- Dados sensiveis em PDF: mapa de pessoal [8] e dados orcamentais [12].
- Ameacas e agentes: phishing dirigido com nomes de funcionarios [8] e emails `@mun-sines.pt` [3][7].
- Abuso de informacao de contratacao [15][16].
- Superficie de ataque: portais web, area de servicos online [18], documentos publicos, formularios de pesquisa.
- Vetores de ataque: engenharia social passiva ancorada no mapa de pessoal [8]; seguimento de concursos e fornecedores [15][16].

## Sources

[1] https://www.sines.pt
[3] https://www.gov.pt/entidades/camara-municipal-de-sines
[5] https://portalautarquico.dgal.gov.pt/pt-PT/entidades-locais/concelhos/sines
[6] https://www.sines.pt/pages/343
[7] https://www.sines.pt/cmsines/uploads/writer_file/document/2147/councillor_helder_guerreiro.pdf
[8] https://www.sines.pt/cmsines/uploads/document/file/12471/despacho_20250509___afetacao_e_reafetacao_dos_trabalhadores_do_mapa_de_pessoal_da_camara_municipal_de_sines.pdf
[10] https://www.sines.pt/uploads/document/file/1471/Relat_rio_Anual_de_Avalia__o_de_2010_e_actualiza__o_do_plano_para_2011.pdf
[12] https://www.sines.pt/cmsines/uploads/document/file/12287/grandes_opcoes_do_plano_e_orcamento_2025_2029.pdf
[13] https://crt.sh/?q=%.sines.pt&output=json
[14] http://web.archive.org/cdx/search/cdx?url=sines.pt/*&output=json&filter=statuscode:200&fl=timestamp,original&collapse=digest&limit=20
[15] https://www.sines.pt/pages/302
[15] https://stat.ripe.net/data/network-info/data.json?resource=195.23.140.168
[16] https://www.sines.pt/pages/862?news_id=3969
[17] https://www.sines.pt/pages/1512
[18] https://servicosonline.sines.pt
