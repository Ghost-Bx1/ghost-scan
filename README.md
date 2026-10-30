# Ghost-Scan

**Async Port Scanner & Service Fingerprinter**  
By Gh0st-Bx1 | github.com/Ghost-Bx1

---

## Descricao

Ghost-Scan e um scanner de portas assincrono de alta performance com fingerprinting de servicos, deteccao de OS via TTL, correlacao de CVEs, suporte a CIDR e exportacao no formato Nmap XML. Construido com stdlib Python 3 pura - sem dependencias externas.

## Recursos

- **TCP Async** - Scanner assinccrono com controle de taxa via Semaphore
- **Banner Grabbing** - Probes especificos por porta para captura de banners
- **OS Detection** - Estimativa de OS pelo TTL do ping (Linux/Windows/Cisco)
- **UDP Scan** - Probes UDP para DNS, SNMP, NTP, TFTP
- **CVE Correlation** - Correlacao de CVEs pelo banner do servico
- **CIDR Support** - Expansao de ranges CIDR (limite /16)
- **Nmap XML Export** - Exportacao compativel com parsers Nmap
- **JSON Output** - Resultados estruturados em JSON

## Uso

```bash
python ghost-scan.py -t <alvo> [opcoes]
```

### Argumentos

| Argumento | Descricao |
|-----------|-----------|
| `-t, --target` | IP, hostname ou CIDR (ex: 192.168.1.0/24) |
| `-p, --ports` | top100, full, 1-1024, 22,80,443 (padrao: top100) |
| `--rate` | Conexoes simultaneas (padrao: 500) |
| `--timeout` | Timeout por porta em segundos (padrao: 1.0) |
| `--banner` | Habilitar banner grabbing |
| `--udp` | Habilitar scan UDP |
| `--os-detect` | Deteccao de OS via TTL |
| `-o, --output` | Salvar resultados em JSON |
| `--nmap-xml` | Exportar no formato Nmap XML |
| `--verbose` | Saida detalhada |

### Exemplos

```bash
# Scan rapido das top 100 portas
python ghost-scan.py -t 192.168.1.1

# Scan completo com banner e deteccao de OS
python ghost-scan.py -t 192.168.1.1 -p full --banner --os-detect

# Scan de range de portas com UDP
python ghost-scan.py -t 10.0.0.1 -p 1-1024 --udp --banner

# Scan de rede CIDR com exportacao Nmap XML
python ghost-scan.py -t 192.168.1.0/24 -p top100 --nmap-xml scan.xml

# Scan salvo em JSON
python ghost-scan.py -t 192.168.1.1 -p 22,80,443,8080,8443 -o resultado.json

# Alta velocidade com rate limiting
python ghost-scan.py -t 10.0.0.1 -p full --rate 1000 --timeout 0.5
```

## Correlacao de CVEs

O Ghost-Scan inclui uma base de dados de CVEs correlacionados por banner. Quando um banner e capturado, o scanner automaticamente busca vulnerabilidades conhecidas pelo nome/versao do produto.

Exemplos de correlacoes incluidas:
- OpenSSH versoes vulneraveis
- Apache/IIS versoes desatualizadas
- Exim, Postfix
- WordPress, phpMyAdmin
- E mais...

## OS Detection via TTL

| TTL | Sistema Operacional Estimado |
|-----|------------------------------|
| <= 64 | Linux / Unix |
| <= 128 | Windows |
| <= 255 | Cisco / Roteador |

## Formato Nmap XML

O arquivo exportado e compativel com ferramentas que consomem output Nmap, incluindo parsers e frameworks de pentest.

## Requisitos

- Python 3.7+
- Stdlib apenas (asyncio, socket, subprocess, etc.)

## Aviso Legal

Esta ferramenta foi desenvolvida para testes de seguranca autorizados, CTF, pesquisa e uso defensivo. Use apenas em sistemas que voce tem permissao para testar.

---

*Ghost-Scan v1.0.0 - Ghost Tools Arsenal*
