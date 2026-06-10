import argparse
import json
import sys
from pathlib import Path
from core.parser_python import analyze_python_file
from core.parser_nodejs import analyze_nodejs_file

BANNER = """\033[94m
    ___               _     ______ _               
   / _ \             (_)    |  ___| |              
  / /_\ \ ___  __ _ _ ___  | |_  | | _____      __
  |  _  |/ _ \/ _` | / __| |  _| | |/ _ \ \ /\ / /
  | | | |  __/ (_| | \__ \ | |   | | (_) \ V  V / 
  \_| |_/\___|\__, |_|___/ \_|   |_|\___/ \_/\_/  
               __/ |
              |___/        [IDOR & Logic Scanner]
\033[0m"""

def load_rules(rules_path: str) -> dict:
    try:
        with open(rules_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        print(f"\033[91m[-] Erro ao carregar arquivo de regras: {e}\033[0m")
        sys.exit(1)

def main():
    print(BANNER)
    parser = argparse.ArgumentParser(description="AegisFlow - Scanner Estático de IDOR")
    parser.add_argument("-p", "--path", required=True, help="Caminho do diretório ou arquivo para análise")
    parser.add_argument("-r", "--rules", default="rules/rules.json", help="Caminho do arquivo de regras JSON")
    parser.add_argument("-f", "--format", choices=["text", "json"], default="text", help="Formato de saída")
    
    args = parser.parse_args()
    rules = load_rules(args.rules)
    
    target_path = Path(args.path)
    if not target_path.exists():
        print(f"\033[91m[-] Caminho especificado não existe: {target_path}\033[0m")
        sys.exit(1)

    all_findings = []
    
    # Coleta arquivos para análise
    files_to_scan = []
    if target_path.is_file():
        files_to_scan.append(target_path)
    else:
        files_to_scan.extend(target_path.rglob("*.py"))
        files_to_scan.extend(target_path.rglob("*.js"))

    print(f"[*] Iniciando varredura em {len(files_to_scan)} arquivo(s)...\n")

    for file_path in files_to_scan:
        if file_path.suffix == ".py":
            findings = analyze_python_file(file_path, rules["python"])
            all_findings.extend(findings)
        elif file_path.suffix == ".js":
            findings = analyze_nodejs_file(file_path, rules["nodejs"])
            all_findings.extend(findings)

    # Exibição dos resultados
    if args.format == "json":
        output = [f.to_dict() for f in all_findings]
        print(json.dumps(output, indent=2, ensure_ascii=False))
    else:
        if not all_findings:
            print("\033[92m[+] Nenhum fluxo de IDOR suspeito foi detectado! Bom trabalho.\033[0m")
        else:
            print(f"\033[91m[!] Alerta: {len(all_findings)} potenciais vulnerabilidades encontradas:\033[0m\n")
            for idx, finding in enumerate(all_findings, 1):
                print(f"\033[93m[Achado #{idx}] {finding.vulnerability_type}\033[0m")
                print(f"  \033[1mArquivo:\033[0m {finding.file_path}:{finding.line_number}")
                print(f"  \033[1mSeveridade:\033[0m {finding.severity}")
                print(f"  \033[1mSource:\033[0m {finding.source}")
                print(f"  \033[1mSink:\033[0m {finding.sink}")
                print(f"  \033[1mDescrição:\033[0m {finding.description}")
                print(f"  \033[1mCódigo:\033[0m \033[90m{finding.code_snippet}\033[0m")
                print("-" * 80)

if __name__ == "__main__":
    main()
