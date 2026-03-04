import json
import sys
import argparse
import logging
import time
from datetime import datetime
import os
import urllib.request

def carregar_env(caminho=".env"):
    if os.path.exists(caminho):
        with open(caminho, "r", encoding="utf-8") as f:
            for linha in f:
                linha = linha.strip()
                if linha and "=" in linha and not linha.startswith("#"):
                    chave, valor = linha.split("=", 1)
                    os.environ[chave.strip()] = valor.strip()

carregar_env()

log_dir = "logs"
if not os.path.exists(log_dir):
    os.mkdir(log_dir)

logger = logging.getLogger("autolog")
logger.setLevel(logging.INFO)
handler = logging.FileHandler(os.path.join(log_dir, "analise.log"), encoding="utf-8")
handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
logger.addHandler(handler)

parser = argparse.ArgumentParser(description="analise de captura de rede em json")
parser.add_argument("--file",   "-f", required=False, default="captura2.json", help="caminho pro json do wireshark")
parser.add_argument("--filter", "-m", required=False, help="metodo http a filtrar (GET, POST...)")
parser.add_argument("--output", "-o", required=False, help="salvar relatorio em .txt")
parser.add_argument("--modelo", "-l", required=False, default="llama3.2", help="modelo ollama")
args = parser.parse_args()

padroessql = ["SELECT", "UNION", "DROP", "INSERT", "UPDATE", "DELETE", "EXEC", "CAST", "CHAR"]
ollamaurl = "http://localhost:11434/api/generate"

def analisar_com_ollama(payload_texto, modelo):
    payload_limpo = payload_texto[:1500].encode("ascii", errors="replace").decode("ascii")

    prompt = (
        "You are a cybersecurity analyst. Analyze this network packet payload captured by Wireshark.\n"
        "Determine if it contains signs of a cyberattack such as SQL Injection, XSS, DoS, reconnaissance, etc.\n\n"
        "Respond ONLY with a JSON object. No markdown, no explanation outside the JSON.\n"
        "Use this exact format:\n"
        "{\n"
        '  "e_ataque": true,\n'
        '  "tipo_ataque": "SQL Injection",\n'
        '  "severidade": "alto",\n'
        '  "explicacao": "O payload contem uma query SQL maliciosa tentando extrair dados da tabela users.",\n'
        '  "mitigacao": "Utilizar prepared statements e validar entradas do usuario no backend."\n'
        "}\n\n"
        "Rules:\n"
        "- e_ataque must be true or false\n"
        "- tipo_ataque must be a real attack name like 'SQL Injection', 'XSS', 'DoS', 'Port Scan', 'Brute Force' — never 'none' or 'attack name'\n"
        "- if no attack is detected, set e_ataque to false and tipo_ataque to 'Nenhum'\n"
        "- severidade must be exactly one of: baixo, medio, alto\n"
        "- explicacao and mitigacao must be in Portuguese\n\n"
        f"Payload to analyze:\n{payload_limpo}"
    )

    body = json.dumps({
        "model":  modelo,
        "prompt": prompt,
        "stream": False
    }, ensure_ascii=True).encode("utf-8")

    req = urllib.request.Request(
        ollamaurl, data=body,
        headers={"Content-Type": "application/json"},
        method="POST"
    )

    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            result = json.loads(resp.read().decode("utf-8"))
            texto = result["response"].strip()
            texto = texto.replace("```json", "").replace("```", "").strip()
            try:
                return json.loads(texto)
            except json.JSONDecodeError:
                inicio = texto.find("{")
                fim    = texto.rfind("}") + 1
                if inicio != -1 and fim > inicio:
                    trecho = texto[inicio:fim]
                    trecho = "".join(c if ord(c) >= 32 or c in "\n\r\t" else " " for c in trecho)
                    return json.loads(trecho)
                raise
    except Exception as e:
        logger.warning(f"Erro ao chamar Ollama: {e}")
        return {
            "e_ataque":    None,
            "tipo_ataque": "erro na analise",
            "severidade":  "desconhecido",
            "explicacao":  f"nao foi possivel analisar: {e}",
            "mitigacao":   "-"
        }

arquivo = args.file
logger.info(f"Iniciando analise: {arquivo}")

with open(arquivo, "r", encoding="utf-8") as f:
    data = json.load(f)

logger.info(f"Tamanho: {len(str(data))} caracteres")

pacotes = None
if isinstance(data, list):
    pacotes = data
elif isinstance(data, dict):
    for chave in data.keys():
        if isinstance(data[chave], list):
            pacotes = data[chave]
            break
    if pacotes is None:
        pacotes = [data]
else:
    pacotes = [data]

logger.info(f"Pacotes encontrados: {len(pacotes)}")
print(f"\narquivo: {arquivo}")
print(f"pacotes encontrados: {len(pacotes)}")

http_num   = 0
filter_num = 0
suspects   = []

for i, pacote in enumerate(pacotes, start=1):
    texto    = str(pacote)
    tem_http = "http" in texto.lower()

    if tem_http:
        http_num += 1

    if args.filter and args.filter.upper() in texto.upper():
        filter_num += 1

    if tem_http:
        for palavra in padroessql:
            if palavra in texto.upper() and not any(s[0] == i for s in suspects):
                suspects.append((i, palavra, texto))
                logger.warning(f"Possivel SQL injection no pacote {i} - padrao: {palavra}")

logger.info(f"Pacotes HTTP: {http_num}")
logger.info(f"Suspeitos: {len(suspects)}")

print(f"pacotes http: {http_num}")
if args.filter:
    print(f"requisicoes {args.filter.upper()}: {filter_num}")
print(f"padroes suspeitos: {len(suspects)}")
for pid, palavra, _ in suspects:
    print(f"  pacote {pid}: {palavra}")

analises_ia = []

if suspects:
    print(f"\nanalisando com ollama ({args.modelo})...")
    logger.info(f"Iniciando analise com Ollama para {len(suspects)} pacotes")

    for pacote_id, palavra, texto_pacote in suspects:
        print(f"  pacote {pacote_id}...", end=" ", flush=True)
        resultado = analisar_com_ollama(texto_pacote, args.modelo)
        analises_ia.append((pacote_id, palavra, resultado))

        sev  = resultado.get("severidade", "?").upper()
        tipo = resultado.get("tipo_ataque", "?")
        print(f"[{sev}] {tipo}")

        logger.info(f"Ollama - pacote {pacote_id}: ataque={resultado.get('e_ataque')}, tipo={tipo}, severidade={sev}")

currenttime = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

linhas = []
linhas.append("=" * 55)
linhas.append("RELATORIO DE ANALISE DE REDE")
linhas.append("=" * 55)
linhas.append(f"data/hora: {currenttime}")
linhas.append(f"arquivo:   {arquivo}")
linhas.append(f"modelo IA: {args.modelo}")
linhas.append("")
linhas.append("RESUMO")
linhas.append("-" * 55)
linhas.append(f"total de pacotes: {len(pacotes)}")
linhas.append(f"pacotes http:     {http_num}")
if args.filter:
    linhas.append(f"req {args.filter.upper()}:          {filter_num}")
linhas.append(f"suspeitos:        {len(suspects)}")
linhas.append("")

if suspects:
    linhas.append("PADROES DETECTADOS")
    linhas.append("-" * 55)
    for pid, palavra, _ in suspects:
        linhas.append(f"  pacote {pid} -> {palavra}")
    linhas.append("")

if analises_ia:
    linhas.append("ANALISE DE IA")
    linhas.append("-" * 55)
    for pid, palavra, res in analises_ia:
        ataque = "[ATAQUE]" if res.get("e_ataque") else "[OK]"
        linhas.append(f"{ataque} pacote {pid}")
        linhas.append(f"  tipo:       {res.get('tipo_ataque')}")
        linhas.append(f"  severidade: {res.get('severidade')}")
        linhas.append(f"  explicacao: {res.get('explicacao')}")
        linhas.append(f"  mitigacao:  {res.get('mitigacao')}")
        linhas.append("")

linhas.append("=" * 55)

print("\n" + "\n".join(linhas))

if args.output:
    pasta = os.path.dirname(args.output)
    if pasta and not os.path.exists(pasta):
        os.makedirs(pasta)
    with open(args.output, "w", encoding="utf-8") as f:
        f.write("\n".join(linhas) + "\n")
    print(f"relatorio salvo: {args.output}")
    logger.info(f"Relatorio salvo em: {args.output}")
else:
    logger.info("Relatorio nao salvo em arquivo.")

logger.info(f"Analise concluida as {datetime.now().strftime('%H:%M:%S')}")
sys.exit(0)