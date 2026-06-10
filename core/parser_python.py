import ast
from pathlib import Path
from typing import List, Dict
from core.models import Finding

class PythonSourceToSinkVisitor(ast.NodeVisitor):
    def __init__(self, file_path: str, rules: Dict[str, List[str]], code_lines: List[str]):
        self.file_path = file_path
        self.rules = rules
        self.code_lines = code_lines
        self.findings: List[Finding] = []

    def visit_FunctionDef(self, node: ast.FunctionDef):
        # Analisa os argumentos da função (Sources em potencial)
        detected_sources = []
        for arg in node.args.args:
            if arg.arg in self.rules["sources"]:
                detected_sources.append(arg.arg)

        if detected_sources:
            # Rastreia o corpo da função em busca de Sinks e Sanitizers
            has_sanitizer = False
            detected_sink = None
            sink_line = 0

            for child in ast.walk(node):
                # Detecta Sanitizers (chamadas de função de validação)
                if isinstance(child, ast.Call):
                    if isinstance(child.func, ast.Name) and child.func.id in self.rules["sanitizers"]:
                        has_sanitizer = True
                    elif isinstance(child.func, ast.Attribute) and child.func.attr in self.rules["sanitizers"]:
                        has_sanitizer = True

                # Detecta Sinks (operações de banco de dados)
                if isinstance(child, ast.Call):
                    func_name = None
                    if isinstance(child.func, ast.Attribute):
                        func_name = child.func.attr
                    elif isinstance(child.func, ast.Name):
                        func_name = child.func.id

                    if func_name in self.rules["sinks"]:
                        detected_sink = func_name
                        sink_line = child.lineno

            # Se encontrou fluxo direto de Source para Sink sem Sanitizer, reporta IDOR
            if detected_sink and not has_sanitizer:
                snippet = self.code_lines[sink_line - 1] if sink_line <= len(self.code_lines) else ""
                if "# aegis-ignore" not in snippet:
                    self.findings.append(Finding(
                        file_path=self.file_path,
                        line_number=sink_line,
                        vulnerability_type="Insecure Direct Object Reference (IDOR)",
                        severity="ALTA",
                        source=f"Parâmetro de rota/função: {', '.join(detected_sources)}",
                        sink=f"Chamada de persistência: {detected_sink}()",
                        description="O parâmetro do usuário flui diretamente para uma consulta de banco de dados sem verificação de propriedade aparente.",
                        code_snippet=snippet
                    ))
        
        self.generic_visit(node)

def analyze_python_file(file_path: Path, rules: Dict[str, List[str]]) -> List[Finding]:
    try:
        content = file_path.read_text(encoding="utf-8")
        lines = content.splitlines()
        tree = ast.parse(content, filename=str(file_path))
        visitor = PythonSourceToSinkVisitor(str(file_path), rules, lines)
        visitor.visit(tree)
        return visitor.findings
    except Exception as e:
        # Retorna lista vazia se houver erro de parsing de sintaxe
        return []
