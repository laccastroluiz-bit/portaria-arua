"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const {test} = require("node:test");

const base = path.resolve(__dirname, "..");
const html = fs.readFileSync(path.join(base, "1 - controle-acesso-motoristas.html"), "utf8");
const scripts = Array.from(html.matchAll(/<script(?:\s[^>]*)?>([\s\S]*?)<\/script>/gi));
const code = scripts[scripts.length - 1]?.[1];
assert.ok(code, "O HTML precisa de script inline principal");

class FakePdf {
  constructor() { this.pages=1; this.current=1; this.items=[]; }
  setFont() {} setFontSize() {} setDrawColor() {} line() {}
  text(content,x,y) { this.items.push({type:"text",content,x,y,page:this.current}); }
  splitTextToSize(value) {
    const pieces = [];
    for (const str of String(value).split("\n")) {
      if (!str) pieces.push("");
      for (let i=0; i<str.length; i+=80) pieces.push(str.slice(i,i+80));
    }
    return pieces;
  }
  addPage() { this.current=++this.pages; }
  setPage(index) { this.current=index; }
  addImage(img,format,x,y,w,h) { this.items.push({type:"image",format,x,y,w,h,page:this.current}); }
  getImageProperties() { return {width:800,height:1200}; }
  output() { return {kind:"fake-pdf"}; }
  save(name) { FakePdf.saves.push(name); }
  get internal() { return {getNumberOfPages:()=>this.pages}; }
}
FakePdf.saves=[];

function boot({withPdf=false,blockedStorage=false}={}) {
  const listeners={}, elements={}, opened=[],alerts=[];
  const element = id => (elements[id] ||= {
    value:"",files:[],style:{},textContent:"",complete:true,naturalWidth:0,
    handlers:{},invalid:false,disabled:false,
    addEventListener(name,cb){ this.handlers[name]=cb; },
    checkValidity(){ return !this.invalid; },
    reportValidity(){ this.reported=true; }, reset(){}, click(){}, appendChild(){}
  });
  const window = {
    jspdf:withPdf?{jsPDF:FakePdf}:undefined,
    addEventListener(name,handler){listeners[name]=handler;},
    open(url){opened.push(url);return{};},print(){window.printed=(window.printed||0)+1;}
  };
  const store = blockedStorage
    ? {getItem(){throw Error("Storage unavailable");},setItem(){throw Error("Storage unavailable");},removeItem(){throw Error("Storage unavailable");}}
    : {getItem(){return null;},setItem(){},removeItem(){}};
  const sandbox={
    window, document:{getElementById:element,createElement(){return {};}},
    navigator:{}, localStorage:store, File:undefined, FileReader:function(){},
    alert(value){alerts.push(value);},confirm(){return true;},
    console:{warn(){},error(){},log(){}}
  };
  vm.runInNewContext(code,sandbox,{timeout:3000});
  assert.equal(typeof listeners.DOMContentLoaded,"function");
  listeners.DOMContentLoaded();
  for(const [id,value] of Object.entries({
    nomeMotorista:"MOTORISTA-TESTE",documento:"DOCUMENTO-TESTE",empresa:"EMPRESA TESTE",
    placa:"ABC1D23",veiculo:"Truck",finalidade:"Carga",destino:"Expedição",
    responsavel:"Responsável",porteiro:"Operador",dataHora:"2026-11-04T11:00",
    statusAprovacao:"APROVADO - Entrada Liberada"
  }))element(id).value=value;
  return {sandbox,listeners,element,window,opened,alerts};
}

test("formulario inicia sem CDN e bloqueia PDF com erro controlado",()=>{
  const a=boot();
  assert.match(a.element("estadoPdf").textContent,/não carregada/);
  assert.throws(()=>a.sandbox.gerarPDF(),/jsPDF não carregada/);
  assert.equal(typeof a.element("fotoPessoaCamera").handlers.change,"function");
});
test("CDN pode carregar depois do formulario",()=>{
  const a=boot();
  a.window.jspdf={jsPDF:FakePdf};
  a.sandbox.atualizarDisponibilidadePdf();
  assert.match(a.element("estadoPdf").textContent,/PDF disponível/);
  assert.equal(a.sandbox.gerarPDF().pages,2);
});
test("observacoes extensas nao ultrapassam a pagina e seis anexos ficam em grade",()=>{
  const a=boot({withPdf:true});
  a.element("observacoes").value="observação ".repeat(1200);
  const pdf=a.sandbox.gerarPDF();
  assert.ok(pdf.pages>2);
  assert.equal(pdf.items.filter(x=>x.type==="text" && x.y>292).length,0);
  assert.equal(pdf.items.filter(x=>x.type==="text"&&String(x.content).includes("Imagem não anexada.")).length,6);
  assert.ok(pdf.items.some(x=>String(x.content).includes("DADOS PESSOAIS")));
});
test("download sem File e Enter sem recarregar o formulario",()=>{
  FakePdf.saves=[];
  const a=boot({withPdf:true});
  a.sandbox.baixarPdfLocal();
  assert.equal(FakePdf.saves.length,1);
  let prevented=false;
  a.element("formControle").handlers.submit({preventDefault(){prevented=true;}});
  assert.equal(prevented,true);
  a.element("formControle").invalid=true;
  a.sandbox.baixarPdfLocal();
  assert.equal(FakePdf.saves.length,1);
});
test("compartilhamento de navegador antigo nao envia PII na URL",async()=>{
  FakePdf.saves=[];
  const a=boot({withPdf:true});
  await a.sandbox.gerarPdfECompartilhar();
  assert.equal(FakePdf.saves.length,1);
  assert.equal(a.opened.length,1);
  assert.ok(a.opened[0].startsWith("https://wa.me/?text="));
  assert.ok(!a.opened[0].includes("MOTORISTA-TESTE"));
  assert.ok(!a.opened[0].includes("DOCUMENTO-TESTE"));
  assert.ok(!a.opened[0].includes("ABC1D23"));
});
test("bloqueio de localStorage nao impede anexar fotos ou validar",()=>{
  const a=boot({blockedStorage:true});
  assert.equal(typeof a.element("fotoPessoaArquivo").handlers.change,"function");
  assert.equal(a.sandbox.validarPreenchimento(true),true);
});
test("arquivos PWA existem; cache nao inclui cadastros ou fotos",()=>{
  const manifest=JSON.parse(fs.readFileSync(path.join(base,"manifest.webmanifest"),"utf8"));
  assert.equal(manifest.start_url,"./index.html");
  assert.equal(manifest.icons[0].src,"./icon-portaria.svg");
  assert.ok(fs.readFileSync(path.join(base,"icon-portaria.svg"),"utf8").includes("<svg"));
  const sw=fs.readFileSync(path.join(base,"sw.js"),"utf8");
  assert.ok(sw.includes("target.origin !== self.location.origin"));
  assert.ok(sw.includes("WHITELIST"));
  assert.ok(!sw.includes("localStorage"));
});
