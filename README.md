```
    ___               _     ______ _               
   / _ \             (_)    |  ___| |              
  / /_\ \ ___  __ _ _ ___  | |_  | | _____      __
  |  _  |/ _ \/ _` | / __| |  _| | |/ _ \ \ /\ / /
  | | | |  __/ (_| | \__ \ | |   | | (_) \ V  V / 
  \_| |_/\___|\__, |_|___/ \_|   |_|\___/ \_/\_/  
               __/ |                              
              |___/        [IDOR & Logic Scanner] 

```

# AegisFlow - Source-to-Sink IDOR Scanner

> **Objetivo:** Analisador estático de código (SAST) focado em rastrear o fluxo de dados (Source-to-Sink) para detectar vulnerabilidades de IDOR (Insecure Direct Object Reference) e falhas de lógica de autorização em APIs Python (FastAPI/Flask) e Node.js (Express).

## Sobre o Projeto
Analisador estático de código (SAST) focado em rastrear o fluxo de dados (Source-to-Sink) para detectar vulnerabilidades de IDOR (Insecure Direct Object Reference) e falhas de lógica de autorização em APIs Python (FastAPI/Flask) e Node.js (Express).

## 🛠️ Tecnologias e Módulos

- **Linguagens principais:** Python
- **Módulos nativos recomendados:** ast, argparse, json, pathlib, re, typing
- **Dependências Externas:**
  - `colorama` (^0.4.6): Colorização de saídas no terminal para relatórios de vulnerabilidade

## 🔒 Configurações de Segurança & Higiene Digital

- **Abordagem defensiva:** `DEFENSIVO`
- **Práticas de higiene digital:** Análise estática de fluxo de dados (Taint Analysis) para prevenção de Broken Access Control.
### Medidas de Mitigação Implementadas:
- **Risco / Ameaça:** Falsos Positivos → **Plano de Mitigação:** Permitir anotações no código como '# aegis-ignore' para suprimir alertas validados manualmente.
- **Risco / Ameaça:** Vazamento de Código-Fonte → **Plano de Mitigação:** O scanner roda 100% localmente, sem enviar telemetria ou trechos de código para servidores externos.

## 💻 Interface de Linha de Comando (CLI)

- **Pre-requisito / Comando:** `aegisflow`
- **Instruções de Inicialização:** `python scanner.py --path <diretorio_ou_arquivo> --rules rules/rules.json`
### Argumentos & Flags Configurados:
- `-p, --path` (string): Caminho do diretório ou arquivo a ser analisado (Exemplo: `./samples`)
- `-r, --rules` (string): Caminho para o arquivo de regras JSON (Exemplo: `rules/rules.json`)
- `-f, --format` (string): Formato de saída: 'text' ou 'json' (Exemplo: `json`)

## 📂 Estrutura de Arquivos Criada

Este repositório foi construído de forma limpa e descompactada contendo os seguintes módulos funcionais:

- `rules/rules.json`
- `core/models.py`
- `core/parser_python.py`
- `core/parser_nodejs.py`
- `scanner.py`
- `samples/vulnerable_api.py`
- `samples/secure_api.py`
- `samples/vulnerable_api.js`

---
*Blueprint gerado com orgulho através do Senior Software Architecture Hub no AI Studio.*