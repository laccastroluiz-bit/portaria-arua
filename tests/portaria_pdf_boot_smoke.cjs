const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");
const path = require("node:path");

const html = fs.readFileSync(path.resolve(__dirname, "../1 - controle-acesso-motoristas.html"), "utf8");
const scripts = Array.from(html.matchAll(/<script(?:\\s[^>]*)?>([\\s\\S]*?)<\\/script>/gi));
assert.ok(scripts.length, "Script inline não encontrado");
const code = scripts[scripts.length - 1][1];

function boot(jspdf) {
  const handlers = {};
  const context = {
    window: {jspdf, addEventListener(name, handler) { handlers[name] = handler; }},
    document: {}, navigator: {}, localStorage: {},
    console: {log() {}, warn() {}, error() {}},
    alert() {}
  };
  vm.runInNewContext(code, context, {timeout: 2000});
  assert.equal(typeof context.gerarPDF, "function");
  assert.equal(typeof context.gerarPdfECompartilhar, "function");
  assert.equal(typeof handlers.beforeinstallprompt, "function");
  return context;
}

const withoutCDN = boot(undefined);
assert.throws(() => withoutCDN.gerarPDF(), /Biblioteca jsPDF não carregada/);
const withCDN = boot({jsPDF: function PdfStub() {}});
assert.ok(withCDN);
console.log("PASSOU: JS inicializa com e sem biblioteca jsPDF; PDF indisponível gera erro controlado");
