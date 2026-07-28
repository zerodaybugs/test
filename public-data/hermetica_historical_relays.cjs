const fs = require('fs');
const path = require('path');
const { principalCV, cvToHex, hexToCV, cvToJSON } = require('@stacks/transactions');

const OUT = '/tmp/hermetica-historical-relays';
const API = 'https://api.hiro.so';
const DEP = 'SPN5AKG35QZSK2M8GAMR4AFX45659RJHDW353HSG';
const STATE = 'minting-auto-state-v1';
const ASSETS = {
  sbtc: 'SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4.sbtc-token',
  aeusdc: 'SP3Y2ZSH8P7D50B0VBTSX11S7XSG24M1VB9YFQA4K.token-aeusdc',
};
const CONTRACTS = [
  'SP3EQA24WCW9XQRP2BPMME17JDX6PXRZPSGKAAR2J.flmintv2',
  'SP6XGBDAD800GGY6XF48AC27467W9PEHA6EPBGKJ.test-hermetica-interface-hbtc3-v1',
  'SP6XGBDAD800GGY6XF48AC27467W9PEHA6EPBGKJ.test-hermetica-interface-hbtc4-v1',
  'SP6XGBDAD800GGY6XF48AC27467W9PEHA6EPBGKJ.test-hermetica-interface-hbtc-v3',
  'SP6XGBDAD800GGY6XF48AC27467W9PEHA6EPBGKJ.test-hermetica-interface-hbtc-v4',
  'SP6XGBDAD800GGY6XF48AC27467W9PEHA6EPBGKJ.test-hermetica-interface-hbtc-v6',
  'SP1A4X1ZFXGE4J28ZQ9QG3JNRCQ4AK6R10PECHVVP.liquidator',
  'SP1EH0FBF8NQTGEBJKF9RJT0AZ5XTNPKJAP0WZJ23.liquidator',
];

const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
async function fetchRetry(url, options = {}, attempts = 10) {
  let last;
  for (let i = 0; i < attempts; i++) {
    try {
      const response = await fetch(url, options);
      const text = await response.text();
      if (response.ok) {
        try { return JSON.parse(text); } catch { return text; }
      }
      last = new Error(`${response.status}: ${text.slice(0, 300)}`);
      if (response.status < 500 && response.status !== 429) throw last;
    } catch (error) { last = error; }
    await sleep(Math.min(12000, 700 * (i + 1)));
  }
  throw last;
}
function unwrap(node) {
  if (node == null || typeof node !== 'object') return node;
  if (Array.isArray(node)) return node.map(unwrap);
  if (Object.prototype.hasOwnProperty.call(node, 'value')) return unwrap(node.value);
  const out = {};
  for (const [key, value] of Object.entries(node)) {
    if (key !== 'type' && key !== 'success') out[key] = unwrap(value);
  }
  return out;
}
async function callRead(contract, fn, args) {
  const body = { sender: DEP, arguments: args.map(cvToHex) };
  const result = await fetchRetry(`${API}/v2/contracts/call-read/${DEP}/${contract}/${fn}`, {
    method: 'POST', headers: {'content-type': 'application/json'}, body: JSON.stringify(body),
  });
  let decoded = null;
  if (result.result) decoded = unwrap(cvToJSON(hexToCV(result.result)));
  return { okay: result.okay, cause: result.cause, result_raw: result.result, decoded };
}
(async () => {
  fs.mkdirSync(OUT, {recursive: true});
  const rows = [];
  for (const contractId of CONTRACTS) {
    const [address, name] = contractId.split('.');
    let source = '', metadata = null, sourceError = null;
    try {
      const sourceBody = await fetchRetry(`${API}/v2/contracts/source/${address}/${name}?proof=0`);
      source = sourceBody.source || '';
      fs.writeFileSync(path.join(OUT, contractId.replace('.', '__') + '.clar'), source);
      metadata = await fetchRetry(`${API}/extended/v1/contract/${contractId}`);
    } catch (error) { sourceError = String(error); }
    const whitelist = {};
    const whitelistErrors = {};
    for (const [label, asset] of Object.entries(ASSETS)) {
      try {
        whitelist[label] = await callRead(STATE, 'get-whitelist', [principalCV(contractId), principalCV(asset)]);
      } catch (error) { whitelistErrors[label] = String(error); }
    }
    const publicFunctions = [...source.matchAll(/\(define-public\s+\(([^\s\)]+)/g)].map(match => match[1]);
    const snippets = publicFunctions.map(fn => {
      const index = source.indexOf(`(define-public (${fn}`);
      return {function: fn, snippet: source.slice(index, index + 1800)};
    });
    rows.push({
      contract_id: contractId,
      source_bytes: Buffer.byteLength(source),
      publish_height: metadata && metadata.block_height,
      tx_id: metadata && metadata.tx_id,
      public_functions: publicFunctions,
      public_function_snippets: snippets,
      source_error: sourceError,
      whitelist,
      whitelist_errors: whitelistErrors,
    });
  }
  const active = [];
  for (const row of rows) {
    for (const [asset, result] of Object.entries(row.whitelist)) {
      const value = result && result.decoded;
      if (value && (value.minter === true || value.redeemer === true)) {
        active.push({contract_id: row.contract_id, asset, whitelist: value});
      }
    }
  }
  const summary = {
    generated_at: new Date().toISOString(),
    source: 'Hiro public read-only APIs',
    assets: ASSETS,
    rows,
    active_contract_permissions: active,
  };
  fs.writeFileSync(path.join(OUT, 'summary.json'), JSON.stringify(summary, null, 2));
  console.log(JSON.stringify(summary, null, 2));
})().catch(error => { console.error(error); process.exit(1); });
