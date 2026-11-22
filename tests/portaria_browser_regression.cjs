// Desenvolvido por: Eng. Luiz Alberto Castro.
// Dados e imagens sintéticos. Nenhum envio real por WhatsApp/Web Share.
const { chromium } = require(process.env.LAC_PLAYWRIGHT_MODULE);
const assert = require('node:assert/strict');
const fs = require('node:fs');
const http = require('node:http');
const path = require('node:path');
const html = fs.readFileSync('1 - controle-acesso-motoristas.html', 'utf8');
const output = process.env.LAC_TEST_OUTPUT || '/tmp/lac-portaria-results';
fs.mkdirSync(output, { recursive: true });
const server = http.createServer((req,res) => {
  if (req.url === '/') { res.writeHead(200, {'Content-Type':'text/html; charset=utf-8'}); res.end(html); }
  else { res.writeHead(404); res.end(); }
});
const records = [];
async function run(name, fn) {
  const start = new Date().toISOString();
  try { await fn(); records.push({name,start,result:'passed'}); console.log('PASS',name); }
  catch(error) { records.push({name,start,result:'failed',error:error.message}); throw error; }
}
(async () => {
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const url = 'http://127.0.0.1:' + server.address().port + '/';
  const browser = await chromium.launch();
  async function pageFor(options = {}) {
    const context = await browser.newContext({acceptDownloads:true,serviceWorkers:'block',viewport:options.mobile?{width:390,height:844}:{width:1280,height:900}});
    const errors = [], alerts = [], opened = [];
    const page = await context.newPage();
    page.on('pageerror', error => errors.push(error.message));
    page.on('dialog', async dialog => { alerts.push(dialog.message()); await dialog.accept(); });
    await context.route('**/*', async route => {
      const address = route.request().url();
      if (address.startsWith(url)) return route.continue();
      if (address === 'https://cdnjs.cloudflare.com/ajax/libs/jspdf/4.2.1/jspdf.umd.min.js' && !options.blockCDN) return route.continue();
      return route.abort();
    });
    await page.addInitScript(({noFile,share,cancel}) => {
      window.__opened = [];
      window.open = (...args) => { window.__opened.push(args); return null; };
      if(noFile) Object.defineProperty(window,'File',{value:undefined,configurable:true});
      if(share) {
        Object.defineProperty(navigator,'canShare',{value:() => true,configurable:true});
        Object.defineProperty(navigator,'share',{value:async data => {
          window.__share = {name:data.files[0].name,type:data.files[0].type,size:data.files[0].size,text:data.text};
          if(cancel) throw new DOMException('Cancelled','AbortError');
        },configurable:true});
      } else {
        Object.defineProperty(navigator,'canShare',{value:undefined,configurable:true});
      }
      window.print = () => { window.__printed = true; };
    }, {noFile:!!options.noFile,share:!!options.share,cancel:!!options.cancel});
    await page.goto(url,{waitUntil:'load'});
    return {context,page,errors,alerts,opened};
  }
  async function fill(page) {
    const values = {nomeMotorista:'Visitante Sintetico',documento:'DOCUMENTO-TESTE',empresa:'EMPRESA FICTICIA',placa:'abc1d23',destino:'SETOR TESTE',responsavel:'AUTORIZADOR TESTE',porteiro:'OPERADOR TESTE'};
    for(const [id,value] of Object.entries(values)) await page.locator('#'+id).fill(value);
    await page.locator('#finalidade').selectOption('Visita');
    await page.locator('#statusAprovacao').selectOption('PENDENTE - Aguardando Validação');
  }
  try {
    await run('formulario, seis fotos e download PDF real', async () => {
      const {context,page,errors} = await pageFor();
      assert.equal(await page.evaluate(() => window.jspdf.jsPDF.version),'4.2.1');
      assert.ok(await page.locator('#dataHora').inputValue());
      await fill(page);
      assert.equal(await page.locator('#placa').inputValue(),'ABC1D23');
      const fields = [['fotoPessoaArquivo','previewPessoa'],['fotoDocumentoArquivo','previewDocumento'],['fotoPlacaArquivo','previewPlaca'],['fotoTipoVeiculoArquivo','previewTipoVeiculo'],['fotoCRLVArquivo','previewCRLV'],['fotoCaminhaoArquivo','previewCaminhao']];
      for(let i=0;i<fields.length;i++) {
        const data = await page.evaluate(i => { const c=document.createElement('canvas');c.width=120;c.height=80;const ctx=c.getContext('2d');ctx.fillStyle=['red','blue','green','orange','purple','black'][i];ctx.fillRect(0,0,120,80);return c.toDataURL('image/png').split(',')[1]; },i);
        await page.locator('#'+fields[i][0]).setInputFiles({name:'imagem-sintetica-'+i+'.png',mimeType:'image/png',buffer:Buffer.from(data,'base64')});
        await page.locator('#'+fields[i][1]+' img').waitFor();
      }
      const result = await page.evaluate(() => { const doc=gerarPDF();const pdf=doc.output();return {header:pdf.slice(0,4),pages:doc.getNumberOfPages(),images:(pdf.match(/\/Subtype \/Image/g)||[]).length,hasName:pdf.includes('Visitante Sintetico'),badImage:pdf.includes('inserir a imagem')}; });
      assert.equal(result.header,'%PDF');assert.ok(result.hasName);assert.ok(result.images>=6);assert.equal(result.badImage,false);
      const pending = page.waitForEvent('download');
      await page.locator('#btnBaixarPDF').click();
      const download = await pending;
      await download.saveAs(path.join(output,'pdf-sintetico.pdf'));
      assert.equal(fs.readFileSync(path.join(output,'pdf-sintetico.pdf')).subarray(0,4).toString(),'%PDF');
      const oldURL=page.url();
      await page.locator('#formControle').evaluate(form=>form.dispatchEvent(new Event('submit',{cancelable:true,bubbles:true})));
      assert.equal(page.url(),oldURL);
      assert.deepEqual(errors,[]);
      await page.screenshot({path:path.join(output,'formulario-desktop.png'),fullPage:true});
      await context.close();
    });
    await run('navegador sem File baixa PDF e nao inclui dados no link WhatsApp', async () => {
      const {context,page,errors} = await pageFor({noFile:true,mobile:true});
      await fill(page);
      const pending=page.waitForEvent('download');await page.locator('#btnCompartilhar').click();await pending;
      const opened=await page.evaluate(()=>window.__opened);
      assert.equal(opened.length,1);
      const text=decodeURIComponent(opened[0][0]);
      for(const marker of ['Visitante Sintetico','DOCUMENTO-TESTE','ABC1D23','EMPRESA FICTICIA']) assert.ok(!text.includes(marker));
      assert.equal(opened[0][2],'noopener,noreferrer');
      assert.equal(await page.locator('#btnCompartilhar').isEnabled(),true);
      assert.deepEqual(errors,[]);
      await page.screenshot({path:path.join(output,'formulario-mobile.png'),fullPage:true});
      await context.close();
    });
    await run('Web Share recebe arquivo PDF sintetico sem enviar dados reais', async () => {
      const {context,page,errors} = await pageFor({share:true});await fill(page);
      await page.locator('#btnCompartilhar').click();
      await page.waitForFunction(()=>window.__share && !document.querySelector('#btnCompartilhar').disabled);
      const data=await page.evaluate(()=>window.__share);
      assert.equal(data.type,'application/pdf');assert.ok(data.size>1000);
      assert.equal(await page.evaluate(()=>window.__opened.length),0);assert.deepEqual(errors,[]);
      await context.close();
    });
    await run('cancelamento do compartilhamento nao produz falso erro', async () => {
      const {context,page,alerts,errors} = await pageFor({share:true,cancel:true});await fill(page);
      await page.locator('#btnCompartilhar').click();
      await page.waitForFunction(()=>window.__share && !document.querySelector('#btnCompartilhar').disabled);
      assert.ok(!alerts.some(a=>/erro|Cancelled/i.test(a)));assert.deepEqual(errors,[]);
      await context.close();
    });
    await run('CDN indisponivel preserva formulario, validacao e impressao', async () => {
      const {context,page,errors,alerts} = await pageFor({blockCDN:true});await fill(page);
      assert.ok(await page.locator('#dataHora').inputValue());
      assert.equal(await page.locator('#pdfStatus').isVisible(),true);
      await page.locator('#btnBaixarPDF').click();
      assert.ok(alerts.some(a=>a.includes('Biblioteca de PDF indisponível')));
      await page.getByRole('button',{name:'IMPRIMIR / SALVAR PDF',exact:true}).click();
      assert.equal(await page.evaluate(()=>window.__printed),true);
      assert.equal(await page.locator('#nomeMotorista').inputValue(),'Visitante Sintetico');
      assert.deepEqual(errors,[]);
      await context.close();
    });
  } finally {
    fs.writeFileSync(path.join(output,'resultados.json'),JSON.stringify({browser:'Chromium Linux',production:false,records},null,2));
    await browser.close();server.close();
  }
})().catch(error=>{console.error(error);server.close();process.exitCode=1;});
