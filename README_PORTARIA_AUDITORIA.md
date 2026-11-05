# Portaria Aruá — revisão em branch separada (04/11/2026)

**Responsável pelo projeto:** Eng. Luiz Alberto Castro.

## Escopo e baseline
Revisão sobre o HTML público do repositório `laccastroluiz-bit/portaria-arua`, branch `audit/portaria-jspdf-fallback-20261104`. **Não é a versão operacional local v3.7.1**, cuja estrutura de login, armazenamento e histórico não foi verificada nesta alteração. Não substituir a pasta da portaria sem backup e homologação na máquina utilizada.

## Melhoria documentada
- Inicialização do formulário mesmo se o CDN do jsPDF estiver indisponível; o carregamento de PDF é assíncrono e conferido apenas no momento da ação.
- Botão **BAIXAR PDF** distinto de **IMPRIMIR** e **COMPARTILHAR**.
- Compartilhamento sem depender da API `File` em navegadores antigos; preserva a alternativa de download local.
- PDF com seis células fotográficas em três linhas e duas colunas, mantendo proporções das imagens sem esticamento.
- Paginação do texto de observações, cabeçalhos e rodapé.
- Validação de campos antes de imprimir, salvar ou compartilhar; pressionar Enter não deve submeter ou recarregar o formulário.
- Proteção básica de rolagem em telas pequenas e ajuda breve no formulário.
- Logo textual de contingência se o arquivo `logo-arua.png` não existir. O símbolo SVG de inicialização do PWA é genérico, **não é a logomarca oficial**.
- Novos arquivos `manifest.webmanifest` e `sw.js` com caminhos corretos; cache restrito a HTML, manifesto e ícone, **sem dados de motoristas, documentos ou fotos**.

## Procedimento de homologação
1. Abrir **cópia** no Chrome/Edge e testar acesso normal, offline e celular.
2. Preencher dados **fictícios** e anexar seis fotos não pessoais.
3. Validar, baixar, imprimir, compartilhar e abrir o PDF. Conferir texto completo, legibilidade e quebra de páginas.
4. Simular bloqueio do CDN: formulário e impressão devem continuar disponíveis; **BAIXAR PDF** dependerá do jsPDF.
5. Confirmar que o botão LIMPAR exige confirmação e preserva o logo configurado.
6. Ao testar PWA, usar HTTPS/localhost: o Service Worker não opera de modo padrão em `file://`. A instalação como aplicativo pode requerer ícones PNG em navegadores específicos.
7. O Windows 7 não é mais suportado pela maioria dos navegadores modernos: validar a versão realmente instalada. Impressão em PDF depende dos recursos do navegador ou impressora virtual.

## Limites
Esta cópia GitHub não tem autenticação, trilha de auditoria, histórico, banco SQL nem sincronização multiusuário. O PDF depende de exportação/arquivamento manual; não alegar persistência automática. Não compartilhar documentos, CNH ou fotografias em canais não autorizados. Nenhum código foi levado à produção nesta branch.

## Volta à versão anterior
Não realizar merge. Se ocorrer merge e houver regressão, reverter os commits desta branch, preservando os arquivos `file.json` e `file (2).js` antigos para rastreabilidade.
