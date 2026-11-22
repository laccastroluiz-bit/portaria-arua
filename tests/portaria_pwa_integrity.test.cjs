// Confirma apenas invariantes estáticas. Não equivale a teste em Windows 7 ou Android.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const html = fs.readFileSync(path.join(__dirname, '..', '1 - controle-acesso-motoristas.html'), 'utf8');
const manifest = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'manifest.webmanifest'), 'utf8'));
const sw = fs.readFileSync(path.join(__dirname, '..', 'sw.js'), 'utf8');

test('manifest e arquivos obrigatórios existem no repositório', () => {
  const files = ['index.html', '1 - controle-acesso-motoristas.html', 'manifest.webmanifest', 'sw.js'];
  for (const file of files) assert.ok(fs.existsSync(path.join(__dirname, '..', file)), file);
  for (const icon of manifest.icons) assert.ok(fs.existsSync(path.join(__dirname, '..', icon.src)), icon.src);
  assert.equal(manifest.start_url, './index.html');
});
test('HTML usa manifest, SW e ícone reais', () => {
  assert.match(html, /rel="manifest" href="manifest\.webmanifest"/);
  assert.match(html, /serviceWorker\.register\("sw\.js"\)/);
  assert.match(html, /id="logoEmpresa" src="icon-portaria\.svg"/);
  assert.doesNotMatch(html, /logo-arua\.png/);
});
test('cache do worker é limitado aos quatro arquivos públicos, sem respostas de terceiros', () => {
  assert.match(sw, /const WHITELIST = new Set/);
  assert.match(sw, /event\.request\.method !== "GET"/);
  assert.match(sw, /target\.origin !== self\.location\.origin/);
  assert.match(sw, /!WHITELIST\.has\(target\.pathname\)/);
  assert.match(sw, /target\.search/);
  assert.equal((sw.match(/^  "\.\//gm) || []).length, 4);
  assert.doesNotMatch(sw, /caches\.open\(CACHE_NAME\)[\s\S]*?caches\.match\(event\.request\)[\s\S]*?event\.request\.url\.includes\(.*api/);
});
test('manifest não promete sincronizar cadastros e não usa URL externa', () => {
  assert.match(manifest.description, /não são sincronizados/i);
  for (const icon of manifest.icons) assert.ok(icon.src.startsWith('./'));
});
