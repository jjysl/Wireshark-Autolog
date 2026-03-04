# Autolog — Analisador de Capturas de Rede com IA

![Python](https://img.shields.io/badge/Python-3.8+-blue?logo=python&logoColor=white)
![Ollama](https://img.shields.io/badge/IA-Ollama%20local-black)
![Security](https://img.shields.io/badge/Secret%20Scanning-ativo-green?logo=github)

Ferramenta em Python que automatiza a análise de capturas de tráfego de rede exportadas pelo **Wireshark**, detecta padrões suspeitos de **SQL Injection** e classifica os ataques encontrados usando um **modelo de IA local via Ollama** — sem enviar dados para serviços externos.

Desenvolvida como projeto acadêmico para as disciplinas de **Coding for Security** e **Hacker Mindset** (FIAP).

---

## Funcionalidades

- Leitura de capturas exportadas pelo Wireshark em formato `.json`
- Contagem de pacotes totais e pacotes HTTP
- Detecção de padrões SQL suspeitos (`SELECT`, `UNION`, `DROP`, `INSERT`, `DELETE`, `EXEC`, `CHAR`) apenas em pacotes HTTP, reduzindo falsos positivos
- Classificação de ataques via IA local (Ollama) com tipo, severidade, explicação e sugestão de mitigação
- Geração de log com timestamps em `logs/analise.log`
- Exportação de relatório em `.txt`
- Suporte a filtro por método HTTP (GET, POST, etc.)
- Carregamento seguro de credenciais via `.env`

---

## Requisitos

- Python 3.8+
- [Ollama](https://ollama.com) instalado e rodando localmente
- Modelo `llama3.2` baixado:

```bash
ollama pull llama3.2
```

---

## Como usar

```bash
# análise básica
python autolog.py -f captura.json

# com relatório salvo
python autolog.py -f captura.json -o relatorio.txt

# filtrando por método HTTP
python autolog.py -f captura.json -m POST -o relatorio.txt

# usando outro modelo Ollama
python autolog.py -f captura.json -l llama3.1 -o relatorio.txt
```

### Argumentos disponíveis

| Argumento  | Atalho | Descrição |
|------------|--------|-----------|
| `--file`   | `-f`   | Caminho para o arquivo JSON exportado pelo Wireshark |
| `--filter` | `-m`   | Filtra pacotes por método HTTP (ex: GET, POST) |
| `--output` | `-o`   | Salva o relatório em arquivo `.txt` |
| `--modelo` | `-l`   | Modelo Ollama a utilizar (padrão: `llama3.2`) |

---

## Credenciais

Se desejar usar uma API externa no lugar do Ollama, crie um arquivo `.env` na raiz do projeto:

```
GeminiKey=sua_key_aqui
```

O arquivo `.env` está no `.gitignore` e nunca será commitado.

---

## Estrutura

```
autolog/
├── autolog.py        # script principal
├── .env              # credenciais locais (não commitado)
├── .gitignore
├── logs/
│   └── analise.log   # log gerado automaticamente
└── relatorio.txt     # relatório de saída (opcional)
```

---

## Validação

O projeto foi testado com capturas geradas pelo **DVWA (Damn Vulnerable Web Application)** rodando em **Kali Linux**, utilizando o Wireshark para capturar tráfego HTTP com requisições GET e POST contendo payloads de SQL Injection.

---

## Autores

- José Rodrigues
- Rafael Martins

**Professor:** Márcio Cruz — FIAP
