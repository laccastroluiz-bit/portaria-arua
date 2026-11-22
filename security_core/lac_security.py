#!/usr/bin/env python3
"""LAC Security Core: auditoria estática, local e somente leitura (Python >=3.10).

Não executa código do projeto auditado, não acessa rede e não altera o projeto.
Desenvolvido por: Eng. Luiz Alberto Castro.
"""
from __future__ import annotations

import argparse
import ast
from collections import Counter
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import tarfile
import sys

VERSION = "2.0.0"
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
EXTENSIONS = {".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".html", ".htm", ".json", ".yaml", ".yml", ".sh", ".ps1", ".sql"}
SPECIAL_FILES = {"requirements.txt", "pipfile", "dockerfile", ".env", ".gitignore", "package.json", "package-lock.json", "pyproject.toml", "setup.cfg"}
SKIP_PARTS = {".git", ".venv", "venv", "node_modules", "dist", "build", "__pycache__", ".next", ".pytest_cache", ".mypy_cache", ".tox", "coverage", ".coverage", ".cache"}
ARCHIVES = (".zip", ".tar", ".tar.gz", ".tar.xz", ".tgz", ".7z", ".rar", ".jar", ".war")
SUPPORTED_TAR = (".tar", ".tar.gz", ".tar.xz", ".tgz")
SECRET_RE = re.compile(r'''(?ix)(?:["']?\b(?:api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|password|passwd|private[_-]?key|client[_-]?secret|webhook[_-]?secret)["']?)\s*[:=]\s*["']([^"'\r\n]{8,})["']''')
ENV_SECRET_RE = re.compile(r"(?i)^\s*(?:export\s+)?[A-Z_]*(?:TOKEN|SECRET|PASSWORD|PASSWD|API_KEY|PRIVATE_KEY)\s*=\s*(\S.{5,})\s*$")
KNOWN_SECRET_RE = re.compile(r"\b(?:ghp_[A-Za-z0-9]{25,}|github_pat_[A-Za-z0-9_]{30,}|AKIA[0-9A-Z]{16})\b|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")
PLACEHOLDER_RE = re.compile(r"(?i)(?:example|placeholder|your[-_ ]|change[-_ ]?me|insert[-_ ]?|dummy|fake|sample|definir_|gerar_|xxxx|\$\{|<[^>]+>|^\*+$|^\.+$)")


@dataclass(frozen=True)
class Finding:
    rule: str
    severity: str
    path: str
    line: int
    description: str
    remediation: str
    confidence: str
    fingerprint: str


def finding(rule: str, severity: str, path: str, line: int, description: str, remediation: str, confidence: str = "MEDIUM") -> Finding:
    fingerprint = hashlib.sha256(f"{rule}|{path}|{line}".encode()).hexdigest()[:16]
    return Finding(rule, severity, path, line, description, remediation, confidence, fingerprint)


def add(found: list[Finding], rule: str, severity: str, path: str, line: int, description: str, remediation: str, confidence: str = "MEDIUM") -> None:
    found.append(finding(rule, severity, path, line, description, remediation, confidence))


def classify_file(path: Path) -> bool:
    return path.suffix.lower() in EXTENSIONS or path.name.lower() in SPECIAL_FILES or path.name.lower().startswith(".env.")


def scan_python(content: str, rel: str, found: list[Finding]) -> None:
    try:
        tree = ast.parse(content, filename=rel)
    except SyntaxError as exc:
        add(found, "PY_SYNTAX", "HIGH", rel, exc.lineno or 1, "Arquivo Python com erro de sintaxe; revisão estática parcial.", "Corrigir sintaxe e repetir auditoria.", "HIGH")
        return
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            fn = node.func
            name = fn.id if isinstance(fn, ast.Name) else (fn.value.id + "." + fn.attr if isinstance(fn, ast.Attribute) and isinstance(fn.value, ast.Name) else "")
            if name in {"eval", "exec", "os.system"}:
                add(found, "PY_DYNAMIC_EXEC", "HIGH", rel, node.lineno, "Execução dinâmica de código/comando identificada.", "Evitar eval/exec/os.system; utilizar APIs seguras e parâmetros explícitos.", "HIGH")
            if name in {"pickle.loads", "pickle.load", "marshal.loads", "marshal.load"}:
                add(found, "PY_DESERIALIZE", "HIGH", rel, node.lineno, "Desserialização capaz de executar conteúdo não confiável.", "Usar JSON e formatos seguros; não desserializar dados de terceiros.", "HIGH")
            if name in {"subprocess.run", "subprocess.call", "subprocess.Popen", "subprocess.check_output", "subprocess.check_call"}:
                if any(kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True for kw in node.keywords):
                    add(found, "PY_SHELL_TRUE", "HIGH", rel, node.lineno, "Subprocesso executa comando via shell.", "Usar lista de argumentos e shell=False; validar entradas.", "HIGH")
            if name.endswith(".run") or name == "run":
                if any(kw.arg == "debug" and isinstance(kw.value, ast.Constant) and kw.value.value is True for kw in node.keywords):
                    add(found, "DEBUG_ENABLED", "HIGH", rel, node.lineno, "Modo debug ligado em chamada de execução.", "Desativar debug no ambiente publicado.", "HIGH")
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id.upper() == "DEBUG" and isinstance(node.value, ast.Constant) and node.value.value is True:
                    add(found, "DEBUG_ENABLED", "HIGH", rel, node.lineno, "DEBUG=True definido em código.", "Configurar debug como False em produção.", "HIGH")


def scan_text(content: str, rel: str, found: list[Finding]) -> None:
    extension = Path(rel).suffix.lower()
    name = Path(rel).name.lower()
    is_js = extension in {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".html", ".htm"}
    for lineno, line in enumerate(content.splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", "//", "<!--", "*")):
            continue
        secret = SECRET_RE.search(line)
        env_secret = ENV_SECRET_RE.search(line) if name == ".env" or name.startswith(".env.") else None
        exposed = (secret.group(1) if secret else env_secret.group(1) if env_secret else None)
        if exposed and not PLACEHOLDER_RE.search(exposed) and len(exposed.strip()) >= 8:
            logical_path = rel.split("!/", 1)[-1].lower()
            is_test = logical_path.startswith("tests/") or "/tests/" in logical_path or PurePosixPath(logical_path).name.startswith("test_")
            severity = "LOW" if is_test else "MEDIUM" if logical_path.startswith("patches/") else "HIGH"
            add(found, "POTENTIAL_SECRET", severity, rel, lineno, "Possível segredo literal no código (valor deliberadamente ocultado); validar se é dado fictício de testes.", "Se verdadeiro, revogar/rotacionar; migrar para gerenciador de segredos e verificar histórico Git.", "MEDIUM")
        if KNOWN_SECRET_RE.search(line):
            add(found, "KNOWN_SECRET_PATTERN", "CRITICAL", rel, lineno, "Padrão reconhecível de credencial/chave privada (valor ocultado).", "Revogar/rotacionar; remover do Git e verificar acessos.", "HIGH")
        if re.search(r"(?i)\bverify\s*=\s*False\b|rejectUnauthorized\s*:\s*false\b|_create_unverified_context\s*\(", line):
            add(found, "TLS_VALIDATION_DISABLED", "HIGH", rel, lineno, "Validação TLS potencialmente desativada.", "Validar certificados TLS e configurar CA confiável.", "HIGH")
        if re.search(r"(?i)\b(?:Access-Control-Allow-Origin)[\"']?\s*[:=]\s*[\"']\*[\"']|\borigins\s*=\s*[\"']\*[\"']", line):
            add(found, "PERMISSIVE_CORS", "MEDIUM", rel, lineno, "CORS liberado para todas as origens; revisar exposição de APIs.", "Limitar origens, métodos e credenciais ao necessário.")
        if is_js:
            if re.search(r"\b(?:eval\s*\(|new\s+Function\s*\()", line):
                add(found, "JS_DYNAMIC_EXEC", "HIGH", rel, lineno, "Execução dinâmica de JavaScript.", "Remover eval/Function, usar funções e parsing seguro.", "HIGH")
            if re.search(r"\.innerHTML\s*=|\.outerHTML\s*=|document\.write\s*\(", line) and not re.search(r"\.(?:innerHTML|outerHTML)\s*=\s*(?:\"\"|'')\s*;?\s*$", line):
                add(found, "DOM_HTML_SINK", "MEDIUM", rel, lineno, "Operação HTML dinâmica que requer análise de XSS.", "Preferir textContent ou sanitização confiável e validar origem dos dados.", "LOW")
            # A direct password/token write is stronger evidence than generic browser persistence.
            if re.search(r"\b(?:localStorage|sessionStorage)\.setItem\s*\(\s*[^,\n]+,\s*(?:password|passwd|senha|accessToken|refreshToken|authToken)\s*\)", line, re.I):
                add(found, "BROWSER_RAW_CREDENTIAL", "HIGH", rel, lineno, "Possível credencial bruta persistida no navegador; revisar origem e transformação.", "Não persistir senhas ou tokens brutos; usar autenticação em servidor e cookies seguros, ou verificador derivado para uso estritamente local.", "HIGH")
            if re.search(r"\b(?:localStorage|sessionStorage)\.getItem\s*\(\s*[^)]*(?:current_user|session|auth|token|password)[^)]*\)", line, re.I):
                add(found, "BROWSER_AUTH_STATE", "MEDIUM", rel, lineno, "Estado de autenticação ou credencial lido de armazenamento manipulável pelo cliente.", "Validar identidade e autorização independentemente do armazenamento local; revisar se é apenas preferência de interface.", "MEDIUM")
            if re.search(r"\b(?:localStorage|sessionStorage)\.setItem\s*\(", line):
                add(found, "BROWSER_STORAGE_REVIEW", "LOW", rel, lineno, "Armazenamento no navegador requer avaliação de confidencialidade e retenção.", "Não armazenar tokens/senhas; avaliar dados pessoais, limpeza e criptografia do lado servidor.", "HIGH")
    if name == "requirements.txt":
        for lineno, line in enumerate(content.splitlines(), 1):
            d = line.strip()
            if not d or d.startswith(("#", "-", ".", "/")):
                continue
            if re.match(r"[a-zA-Z][\w.-]*(?:\[[\w,.-]+\])?(?:\s*(?:>=|~=|!=|>|<|===?)|\s*$)", d) and "==" not in d and " @ " not in d:
                add(found, "PY_DEPENDENCY_NOT_PINNED", "LOW", rel, lineno, "Dependência Python sem versão exata fixa.", "Usar lockfile/testes de atualização e verificar vulnerabilidades regularmente.")
    if name == "package.json":
        try:
            meta = json.loads(content)
            for category in ("dependencies", "devDependencies"):
                for dependency, version in meta.get(category, {}).items():
                    if version in ("*", "latest", ""):
                        add(found, "NODE_UNBOUNDED_DEPENDENCY", "MEDIUM", rel, 1, "Dependência Node sem restrição de versão (nome omitido no relatório).", "Restringir versões e gerar lockfile.", "HIGH")
        except (ValueError, TypeError, AttributeError):
            add(found, "PACKAGE_JSON_INVALID", "MEDIUM", rel, 1, "Manifesto package.json inválido.", "Validar sintaxe JSON e dependências.", "HIGH")



def scan_tar(path: Path, rel: str, found: list[Finding], skipped: list[dict], max_bytes: int, max_files: int, already_scanned: int) -> int:
    """Examina arquivos de tar em memória, SEM extrair nem executar conteúdo."""
    scanned = 0
    if path.stat().st_size > 25_000_000:
        skipped.append({"path": rel, "reason": "archive_compressed_size_limit"})
        return 0
    try:
        with tarfile.open(path, mode="r:*") as archive:
            for item in archive:
                inner = PurePosixPath(item.name)
                if inner.is_absolute() or ".." in inner.parts or "\\" in item.name:
                    skipped.append({"path": rel, "reason": "archive_unsafe_member_path"})
                    continue
                if not item.isfile():
                    continue
                member_path = f"{rel}!/{inner.as_posix()}"
                if any(part in SKIP_PARTS for part in inner.parts):
                    continue
                if not classify_file(Path(inner.as_posix())):
                    continue
                if already_scanned + scanned >= max_files:
                    skipped.append({"path": rel, "reason": "archive_member_limit"})
                    break
                if item.size > max_bytes:
                    skipped.append({"path": member_path, "reason": "archive_member_size_limit"})
                    continue
                stream = archive.extractfile(item)
                if stream is None:
                    skipped.append({"path": member_path, "reason": "archive_member_unreadable"})
                    continue
                raw = stream.read(max_bytes + 1)
                if len(raw) > max_bytes or b"\x00" in raw:
                    skipped.append({"path": member_path, "reason": "archive_member_binary_or_oversized"})
                    continue
                try:
                    content = raw.decode("utf-8")
                except UnicodeError:
                    skipped.append({"path": member_path, "reason": "archive_member_encoding"})
                    continue
                scanned += 1
                if inner.suffix.lower() == ".py":
                    scan_python(content, member_path, found)
                scan_text(content, member_path, found)
    except (tarfile.TarError, OSError, EOFError, ValueError):
        skipped.append({"path": rel, "reason": "archive_read_failure"})
    return scanned

def audit(root: Path, max_bytes: int = 1_000_000, max_files: int = 20_000, additional_excludes: tuple[str, ...] = ()) -> dict:
    root = root.resolve()
    if not root.is_dir():
        raise ValueError("Diretório de auditoria não existe ou não é um diretório.")
    if not (1 <= max_bytes <= 50_000_000 and 1 <= max_files <= 200_000):
        raise ValueError("Limites de arquivos fora do intervalo seguro.")
    found: list[Finding] = []
    skipped: list[dict] = []
    total_scanned = 0
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        rel = path.relative_to(root).as_posix()
        parts = set(path.relative_to(root).parts)
        if parts.intersection(SKIP_PARTS) or any(Path(rel).match(pattern) for pattern in additional_excludes):
            continue
        if rel.startswith("security_core/tests/"):
            continue
        if path.name.lower().endswith(SUPPORTED_TAR):
            total_scanned += scan_tar(path, rel, found, skipped, max_bytes, max_files, total_scanned)
            continue
        if path.name.lower().endswith(ARCHIVES):
            skipped.append({"path": rel, "reason": "archive_not_scanned"})
            continue
        if not classify_file(path):
            continue
        if total_scanned >= max_files:
            skipped.append({"path": rel, "reason": "file_limit_reached"})
            break
        try:
            if path.stat().st_size > max_bytes:
                skipped.append({"path": rel, "reason": "file_size_limit"})
                continue
            raw = path.read_bytes()
            if b"\x00" in raw:
                skipped.append({"path": rel, "reason": "binary_or_invalid_text"})
                continue
            content = raw.decode("utf-8")
        except (OSError, UnicodeError):
            skipped.append({"path": rel, "reason": "unreadable_file"})
            continue
        total_scanned += 1
        if path.suffix.lower() == ".py":
            scan_python(content, rel, found)
        scan_text(content, rel, found)
    found = sorted(set(found), key=lambda f: (f.path, f.line, f.rule, f.severity))
    counts = Counter(f.severity for f in found)
    return {
        "tool": "LAC Security Core", "version": VERSION,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "root_name": root.name,
        "status": "PARTIAL" if skipped else "STATIC_SCAN_COMPLETE",
        "summary": {"files_scanned": total_scanned, "findings": len(found), **{s.lower(): counts[s] for s in SEVERITIES}, "unscanned_files": len(skipped)},
        "coverage": {"source_static_patterns": "executed", "python_ast": "executed_where_applicable", "dependencies_cve": "NOT_EXECUTED", "dynamic_security_testing": "NOT_EXECUTED", "access_control": "NOT_VERIFIED", "backups_restore": "NOT_VERIFIED", "production_environment": "NOT_ACCESSED"},
        "findings": [asdict(f) for f in found], "skipped_files": skipped,
        "limitations": ["Resultados heurísticos exigem revisão humana e não demonstram ausência de falhas.", "Segredos são omitidos do relatório, mas seu histórico no repositório precisa ser analisado separadamente.", "Arquivos compactados fora de TAR suportado, dependências CVE, execução, permissões e recuperação não são auditados por esta rotina."],
    }


def markdown(report: dict) -> str:
    sm = report["summary"]
    rows = ["# LAC Security Core — Relatório de auditoria estática", "", f"**Projeto:** `{report['root_name']}`  ", f"**Situação:** {report['status']}  ", f"**Arquivos verificados:** {sm['files_scanned']}  ", f"**Ocorrências:** {sm['findings']} (críticas {sm['critical']}; altas {sm['high']}; médias {sm['medium']}; baixas {sm['low']})  ", f"**Arquivos não examinados:** {sm['unscanned_files']}", "", "## Achados", ""]
    if not report["findings"]:
        rows.append("Nenhum padrão da assinatura atual foi encontrado. **Isso não comprova segurança da aplicação.**")
    for i, f in enumerate(report["findings"], 1):
        rows.extend([f"### {i}. [{f['severity']}] {f['rule']}", f"- Local: `{f['path']}:{f['line']}`", f"- Evidência: {f['description']}", f"- Ação: {f['remediation']}", f"- Confiança do achado: {f['confidence']}", f"- Identificador: `{f['fingerprint']}`", ""])
    rows.extend(["## Escopo e pendências", ""])
    for name, state in report["coverage"].items():
        rows.append(f"- {name}: **{state}**")
    if report["skipped_files"]:
        rows.extend(["", "## Arquivos não examinados", ""])
        for f in report["skipped_files"][:100]:
            rows.append(f"- `{f['path']}` — {f['reason']}")
        if len(report["skipped_files"]) > 100:
            rows.append("- Lista resumida a 100 itens; consultar JSON integral.")
    rows.extend(["", "## Limitações", ""] + [f"- {v}" for v in report["limitations"]])
    return "\n".join(rows) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Auditoria estática de aplicações (somente leitura, sem rede).")
    parser.add_argument("path", nargs="?", default=".", help="Diretório do código-fonte a ser auditado")
    parser.add_argument("--output", default="security-report", help="Diretório para relatórios JSON e Markdown")
    parser.add_argument("--fail-on", choices=["none", "critical", "high", "medium", "low"], default="critical", help="Falha se houver achado nesse nível ou superior")
    parser.add_argument("--strict", action="store_true", help="Falha também se houver arquivos relevantes não examinados")
    parser.add_argument("--exclude", action="append", default=[], help="Glob extra para ignorar (pode repetir)")
    parser.add_argument("--max-file-bytes", type=int, default=1_000_000)
    parser.add_argument("--max-files", type=int, default=20_000)
    args = parser.parse_args(argv)
    try:
        report = audit(Path(args.path), max_bytes=args.max_file_bytes, max_files=args.max_files, additional_excludes=tuple(args.exclude))
        output = Path(args.output).resolve()
        output.mkdir(parents=True, exist_ok=True)
        (output / "report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        (output / "report.md").write_text(markdown(report), encoding="utf-8")
        sm = report["summary"]
        print(f"LAC Security Core v{VERSION} | {sm['files_scanned']} arquivos | {sm['findings']} achados | {sm['unscanned_files']} não examinados | {report['status']}")
        print(f"Relatórios: {output / 'report.md'} ; {output / 'report.json'}")
        trigger = args.fail_on != "none" and any(sm[s.lower()] for s in SEVERITIES[:SEVERITIES.index(args.fail_on.upper()) + 1])
        return 1 if trigger or (args.strict and sm["unscanned_files"]) else 0
    except (ValueError, OSError) as exc:
        print(f"Erro de auditoria: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
