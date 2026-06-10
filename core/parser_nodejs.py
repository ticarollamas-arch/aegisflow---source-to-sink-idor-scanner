import re
from pathlib import Path
from typing import List, Dict
from core.models import Finding

def analyze_nodejs_file(file_path: Path, rules: Dict[str, List[str]]) -> List[Finding]:
    findings: List[Finding] = []
    try:
        content = file_path.read_text(encoding="utf-8")
        lines = content.splitlines()
        
        # Padrões simples para identificar rotas Express e fluxos de dados
        # Exemplo: router.get('/:id', async (req, res) => { ... })
        route_pattern = re.compile(r"\.(get|post|put|delete|patch)\s*\(\s*['\"].*?:(\w+)")
        
        for idx, line in enumerate(lines):
            route_match = route_pattern.search(line)
            if route_match:
                source_param = route_match.group(2)
                
                # Escopo de busca simplificado: próximas 25 linhas
                scope_lines = lines[idx:idx+25]
                scope_text = "\n".join(scope_lines)
                
                # Verifica se há um Sink no escopo
                detected_sink = None
                sink_line_offset = 0
                for s_idx, s_line in enumerate(scope_lines):
                    for sink in rules["sinks"]:
                        if sink in s_line:
                            detected_sink = sink
                            sink_line_offset = s_idx
                            break
                    if detected_sink: 
                        break
                
                # Verifica se há um Sanitizer no escopo
                has_sanitizer = False
                for sanitizer in rules["sanitizers"]:
                    if sanitizer in scope_text:
                        has_sanitizer = True
                        break
                
                if detected_sink and not has_sanitizer:
                    vuln_line = idx + sink_line_offset + 1
                    snippet = lines[vuln_line - 1] if vuln_line <= len(lines) else ""
                    if "// aegis-ignore" not in snippet:
                        findings.append(Finding(
                            file_path=str(file_path),
                            line_number=vuln_line,
                            vulnerability_type="Insecure Direct Object Reference (IDOR)",
                            severity="ALTA",
                            source=f"Parâmetro de rota Express: :{source_param}",
                            sink=f"Chamada de banco/ORM: {detected_sink}",
                            description="Parâmetro de rota flui para consulta de banco de dados sem validação de propriedade (Sanitizer/Guard).",
                            code_snippet=snippet
                        ))
    except Exception:
        pass
    return findings
