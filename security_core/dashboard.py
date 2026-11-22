#!/usr/bin/env python3
"""Offline, privacy-preserving dashboard from redacted LAC v3 summary only."""
import argparse
from html import escape
import json
from pathlib import Path

NUMERIC_FIELDS = ("lac_files","lac_findings","lac_high","lac_critical","lac_unscanned",
                  "gitleaks_potential_secrets","semgrep_findings","semgrep_error_severity",
                  "semgrep_warning_severity","semgrep_scan_errors")
LABELS = {
 "lac_files":"Arquivos examinados","lac_findings":"Achados estáticos LAC",
 "lac_high":"Alertas altos LAC","lac_critical":"Alertas críticos LAC",
 "lac_unscanned":"Arquivos não examinados","gitleaks_potential_secrets":"Possíveis segredos no Git",
 "semgrep_findings":"Achados Semgrep","semgrep_error_severity":"Regras Semgrep de nível ERROR",
 "semgrep_warning_severity":"Alertas Semgrep WARNING","semgrep_scan_errors":"Erros do Semgrep"
}
STATUS = {
 "INCOMPLETE":("Verificação incompleta","warning"),
 "BLOCKED_REVIEW":("Bloqueado para revisão","danger"),
 "REVIEW_REQUIRED":("Revisão necessária","warning"),
 "AUTOMATED_CHECKS_CLEAR":("Verificações automáticas sem alertas","ok")
}
def render(data: dict) -> str:
    if not isinstance(data,dict) or data.get("tool")!="LAC Cybersecurity Suite" or data.get("version")!="3.0.0":
        raise ValueError("Only v3 sanitized summaries are accepted")
    if data.get("production_approved") is not False:
        raise ValueError("An automated scanner cannot approve production")
    if data.get("status") not in STATUS or not isinstance(data.get("results"),dict):
        raise ValueError("Invalid status/results")
    results=data["results"]
    if any(type(results.get(k)) is not int or results[k]<0 for k in NUMERIC_FIELDS):
        raise ValueError("Invalid metric")
    name,cls=STATUS[data["status"]]
    cards="\n".join('<section class="metric"><small>'+escape(LABELS[k])+
                  '</small><strong>'+str(results[k])+'</strong></section>' for k in NUMERIC_FIELDS)
    return f'''<!doctype html>
<html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; object-src 'none'">
<title>LAC Security Center — Auditoria</title>
<style>
:root{{color-scheme:dark;font-family:system-ui,sans-serif;background:#090f1e;color:#e8eef9}}
body{{max-width:1060px;margin:0 auto;padding:clamp(16px,4vw,36px)}}
h1{{font-size:clamp(23px,4vw,34px)}}p,small{{color:#aab9cf}}.note{{padding:14px 18px;border:1px solid #455573;border-radius:12px;margin:22px 0}}
.status{{display:inline-block;border:1px solid;padding:10px 14px;border-radius:30px;font-weight:700}}
.warning{{color:#fbbf24}}.danger{{color:#ff8181}}.ok{{color:#7ddbb3}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px;margin:28px 0}}
.metric{{background:#152136;border:1px solid #2b405e;border-radius:14px;padding:18px}}
.metric small{{display:block;min-height:35px}}.metric strong{{display:block;font-size:30px;margin-top:9px}}
footer{{font-size:12px;margin-top:40px;color:#aab9cf}}
</style></head><body>
<header><h1>🛡️ LAC Security Center</h1>
<p>Painel local de auditoria estática — sem acesso à produção e sem credenciais</p></header>
<div class="status {cls}">{escape(name)}</div>
<div class="grid">{cards}</div>
<section class="note"><strong>Homologação para produção: NÃO CONCEDIDA.</strong>
<p>Os scanners cobrem apenas parte da segurança. Os dados de autenticação real, permissões,
ambiente em execução, backup, privacidade e incidentes exigem evidência independente.</p></section>
<footer>Relatório sanitizado · LAC Cybersecurity Suite v3 · Desenvolvido por: Eng. Luiz Alberto Castro</footer>
</body></html>'''

def main(argv=None):
    parser=argparse.ArgumentParser()
    parser.add_argument("summary")
    parser.add_argument("--output",required=True)
    args=parser.parse_args(argv)
    data=json.loads(Path(args.summary).read_text(encoding="utf-8"))
    Path(args.output).write_text(render(data),encoding="utf-8")
if __name__=="__main__":
    main()
