# TPDE - Grupo 12 - Recon Passiva

## Ficha de Reconhecimento Passivo - Camara Municipal de Sines

> TLDR: worksheet de recon passiva, Grupo 12, sem scan ativo.

Alvo: Camara Municipal de Sines (Moodle, 16 Nov 2026).
Permitido: passivo + dirbuster leve (wordlist curta, poucos threads, sem autenticacao, sem exploits).
Proibido: Nmap, Nessus, Nikto, ataques reais e bruteforce massivo.
Usar WHOIS/RDAP, DNS publico, Shodan, Censys, CT, motores de busca, arquivos.
Merge com o Gelson: comparar outputs e consolidar no relatorio LaTeX.

### 1. Identificacao da Organizacao e Presenca Fisica

#### a) Sede e filiais: localizacao exata e mapeamento de instalacoes

- `whois cm-sines.pt`
- `curl -s https://rdap.org/domain/cm-sines.pt`
- `dig +short cm-sines.pt A AAAA MX NS TXT`
- Dorks Google/DDG:
  - `site:cm-sines.pt "morada" OR "contactos"`
  - `"Camara Municipal de Sines" "morada"`
  - `site:google.com/maps "Camara Municipal de Sines"`

**Info encontrada:**
- [ ] preencher com morada, coordenadas e filiais

#### b) Seguranca fisica: perimetros, camaras e controlos de acesso via satelite/imagens publicas

- `curl -s "https://nominatim.openstreetmap.org/search?q=Camara%20Municipal%20de%20Sines&format=json"`
- Dorks Google/DDG:
  - `site:google.com/maps "Camara Municipal de Sines"`
  - `"Camara Municipal de Sines" "camaras" OR "seguranca" OR "acesso"`
  - `site:cm-sines.pt "instalacoes" OR "edificio"`

**Info encontrada:**
- [ ] preencher com observacoes visuais e fontes

### 2. Pegada Logica e de Infraestrutura (Footprinting)

#### a) Propriedades de dominio: WHOIS, subdominios e historico DNS

- `whois cm-sines.pt`
- `dig cm-sines.pt ANY +noall +answer`
- `subfinder -d cm-sines.pt -o recon/subfinder.txt`
- `amass enum -passive -d cm-sines.pt -o recon/amass.txt`
- `assetfinder --subs-only cm-sines.pt | sort -u > recon/assetfinder.txt`
- `curl -s "https://crt.sh/?q=%.cm-sines.pt&output=json" -o recon/crtsh.json`
- Dorks Google/DDG:
  - `site:lookup.icann.org "cm-sines.pt"`
  - `site:crt.sh "cm-sines.pt"`
  - `"cm-sines.pt" -site:cm-sines.pt`

**Info encontrada:**
- [ ] preencher com registo, subdominios e historico

#### b) Enderecamento IP: netblocks, ASN e topologia externa

- `whois <IP>`
- `curl -s "https://stat.ripe.net/data/prefix-overview/data.json?resource=<IP>"`
- `curl -s "https://rdap.org/ip/<IP>"`
- Dorks Google/DDG:
  - `site:bgp.he.net "Camara Municipal de Sines"`
  - `site:ripe.net "cm-sines.pt"`
  - `site:censys.io "cm-sines.pt"`

**Info encontrada:**
- [ ] preencher com IPs, CIDRs, ASN e provedores

#### c) Servicos externos: cloud, VPN, Citrix, e-mail, favicon e tecnologias

- `dig cm-sines.pt MX TXT`
- `cloudenum cm-sines.pt` (ou `python3 cloudenum.py -d cm-sines.pt`)
- `curl -s "https://mxtoolbox.com/SuperTool.aspx?action=mx%3acm-sines.pt"`
- Shodan:
  - `hostname:"cm-sines.pt"`
  - `http.title:"AnyConnect" "Sines"`
  - `product:"Citrix" "Sines"`
  - `http.favicon.hash:<hash>` (hash via Shodan, sem GET ao alvo)
- Dorks Google/DDG:
  - `site:cm-sines.pt "vpn" OR "citrix" OR "office365" OR "webmail"`
  - `site:grayhatwarfare.com "sines"`
  - `site:builtwith.com "cm-sines.pt"`

**Info encontrada:**
- [ ] preencher com servicos, portas publicas e tecnologias

### 3. Analise de Metadados e Ficheiros Expostos

#### a) Metadados de documentos publicos (PDF, DOCX, XLSX)

- `metagoofil -d cm-sines.pt -t pdf,docx,xlsx -l 20 -o recon/files/`
- `exiftool recon/files/<ficheiro>`
- `pdfinfo recon/files/<ficheiro>`
- `strings recon/files/<ficheiro> | head -50`
- Dorks Google/DDG:
  - `site:cm-sines.pt filetype:pdf`
  - `site:cm-sines.pt filetype:doc OR filetype:docx OR filetype:xlsx`
  - `site:cm-sines.pt "confidencial" OR "interno"`

**Info encontrada:**
- [ ] preencher com nomes, software, impressoras e caminhos de rede

#### b) Fugas de credenciais ou dados em repositorios de terceiros

- `theHarvester -d cm-sines.pt -b all -f recon/harvester.html`
- `gitleaks detect --source <repo-publico> --report-path recon/gitleaks.json`
- Dorks Google/DDG:
  - `site:github.com "cm-sines.pt"`
  - `site:pastebin.com "cm-sines.pt"`
  - `"@cm-sines.pt" "password" OR "senha"`

**Info encontrada:**
- [ ] preencher com credenciais/dados expostos e fonte

#### c) Historico web: paginas e ficheiros removidos

- `curl -s "http://web.archive.org/cdx/search/cdx?url=cm-sines.pt/*&output=json&filter=statuscode:200&fl=timestamp,original&collapse=digest" -o recon/wayback.json`
- `curl -s "https://web.archive.org/web/20200101000000/http://www.cm-sines.pt/"`
- Dorks Google/DDG:
  - `site:web.archive.org/web "cm-sines.pt"`
  - `"cm-sines.pt" "filetype:pdf" "arquivo"`

**Info encontrada:**
- [ ] preencher com URLs antigas e ficheiros sensiveis

#### d) Enumeracao muito leve de diretorios (opcional)

- Limites: wordlist curta, 1-2 threads, sem recursao, sem login, sem payloads, sem exploits
- `gobuster dir -u https://www.cm-sines.pt -w /usr/share/wordlists/dirb/common.txt -t 2 -q -o recon/gobuster.txt`
- `dirb https://www.cm-sines.pt/ /usr/share/dirb/wordlists/small.txt -o recon/dirb.txt`
- Alternativa passiva (sem pedidos ao alvo):
  - `site:cm-sines.pt inurl:/admin/ OR inurl:/backup/ OR inurl:/uploads/`
  - `site:cm-sines.pt intitle:"index of"`

**Info encontrada:**
- [ ] preencher com diretorios/ficheiros e decidir se o pedido foi minimo

### 4. Inteligencia sobre Colaboradores

#### a) Estrutura organizacional, cargos e departamentos

- Dorks Google/DDG:
  - `site:linkedin.com/company "Camara Municipal de Sines"`
  - `site:linkedin.com/in "Camara Municipal de Sines"`
  - `site:facebook.com "Camara Municipal de Sines"`
  - `"Camara Municipal de Sines" "diretor" OR "chefe de divisao"`

**Info encontrada:**
- [ ] preencher com nomes, cargos e hierarquia

#### b) Formato do e-mail institucional

- `theHarvester -d cm-sines.pt -b google,bing,duckduckgo -l 200 -f recon/emails.html`
- Dorks Google/DDG:
  - `"@cm-sines.pt"`
  - `site:cm-sines.pt "@"`
  - `"primeiro.apelido@cm-sines.pt"`

**Info encontrada:**
- [ ] preencher com padrao de e-mail e exemplos

#### c) Exposicao de e-mails corporativos em fugas

- Dorks Google/DDG:
  - `"@cm-sines.pt" site:haveibeenpwned.com`
  - `"@cm-sines.pt" "breach" OR "vazamento"`
  - `site:dehashed.com "cm-sines.pt"`

**Info encontrada:**
- [ ] preencher com dominios encontrados em bases de fuga

### 5. Informacao de Negocio e Relacionamentos

#### a) Parceiros e fornecedores com acesso a infraestrutura

- Dorks Google/DDG:
  - `site:cm-sines.pt "parceiro" OR "fornecedor"`
  - `site:base.gov.pt "Camara Municipal de Sines"`
  - `site:cm-sines.pt "ajuste direto" OR "contrato"`

**Info encontrada:**
- [ ] preencher com entidades terceiras e relacao

#### b) Dados financeiros, aquisicoes e tecnologias criticas

- Dorks Google/DDG:
  - `site:cm-sines.pt "relatorio anual" OR "orcamento"`
  - `site:cm-sines.pt "relatorio de gestao" filetype:pdf`
  - `"Camara Municipal de Sines" "tecnologia" OR "contrato"`

**Info encontrada:**
- [ ] preencher com fontes e valores

### 6. Modelacao de Ameacas

- Ativos criticos: listar dominios, portais, dados e servicos das seccoes 1-5
- Ameacas e agentes: pesquisar ataques a entidades/sistemas semelhantes
  - Dorks: `"camara municipal" ransomware`, `"autarquia" ataque cibernetico`, `site:incidentdatabase.io "municipality"`
- Superficie de ataque: formularios, logins, versoes antigas e ficheiros expostos
- Vetores de ataque: justificar cada um com evidencia passiva

**Info encontrada:**
- [ ] preencher com ativos, ameacas, superficie e vetores
