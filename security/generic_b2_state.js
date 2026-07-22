'use strict';
const fs = require('fs');
const { ethers } = require('ethers');

const OUT = 'b2-state-output';
const EXPECTED_CHAIN_ID = 223;
const RPCS = [
  'https://rpc.bsquared.network',
  'https://mainnet.b2-rpc.com',
  'https://b2-mainnet.alt.technology',
  'https://b2-mainnet-public.s.chainbase.com',
  'https://rpc.ankr.com/b2',
  'https://223.rpc.thirdweb.com',
];
const BLOCKSCOUT = 'https://explorer.bsquared.network';
const addresses = {
  routerA: ethers.utils.getAddress('0x3cb5fa87703c7165cc5f2087B3e80b58fb6d8CE8'),
  routerB: ethers.utils.getAddress('0x830fBad7Cd1c3Cc5B693Dc64b985f2901B253C5B'),
  component: ethers.utils.getAddress('0xBd795F755dbB5A5358D6c60AED53ceB486Fa8517'),
  registry: ethers.utils.getAddress('0x03c4FCF963E5FBC0dC5851d2340624E70492acb9'),
};
const IMPLEMENTATION_SLOT = '0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc';
const ADMIN_SLOT = '0xb53127684a568b3173ae13b9f8a6016e019c32180d6a85049e47d4c6f475e6103';
const routerAAbi = [
  'function owner() view returns(address)',
  'function paused() view returns(bool)',
  'function adapterWhitelist(address) view returns(bool)',
];
const routerBAbi = [
  'function owner() view returns(address)',
  'function paused() view returns(bool)',
  'function adapterWhitelist(address) view returns(bool)',
  'function whitelistManager() view returns(address)',
  'function defaultWhitelistModule() view returns(uint8)',
];
const registryAbi = [
  'function isWhitelisted(address,uint8) view returns(bool)',
  'function owner() view returns(address)',
];
const erc20Abi = [
  'function balanceOf(address) view returns(uint256)',
  'function decimals() view returns(uint8)',
  'function symbol() view returns(string)',
  'function name() view returns(string)',
  'function totalSupply() view returns(uint256)',
];

function serialise(x) {
  if (ethers.BigNumber.isBigNumber(x)) return x.toString();
  if (Array.isArray(x)) return x.map(serialise);
  if (x && typeof x === 'object') {
    const o = {};
    for (const [k, v] of Object.entries(x)) if (!/^\d+$/.test(k)) o[k] = serialise(v);
    return o;
  }
  return x;
}
async function safe(promise) {
  try { return { ok: true, value: serialise(await promise) }; }
  catch (e) { return { ok: false, error: String(e && e.stack ? e.stack : e) }; }
}
async function getJson(url, timeout = 25000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);
  try {
    const r = await fetch(url, { headers: { accept: 'application/json', 'user-agent': 'generic-readonly-state/1.0' }, signal: controller.signal });
    const text = await r.text();
    if (!r.ok) throw new Error(`HTTP ${r.status}: ${text.slice(0, 500)}`);
    try { return JSON.parse(text); } catch { return text; }
  } finally { clearTimeout(timer); }
}
async function provider() {
  const attempts = [];
  for (const url of RPCS) {
    try {
      const p = new ethers.providers.StaticJsonRpcProvider(url, { chainId: EXPECTED_CHAIN_ID, name: 'b2' });
      const [n, b] = await Promise.all([p.getNetwork(), p.getBlockNumber()]);
      if (n.chainId !== EXPECTED_CHAIN_ID) throw new Error(`wrong chain ${n.chainId}`);
      const block = await p.getBlock(b);
      attempts.push({ url, ok: true, chainId: n.chainId, blockNumber: b, blockHash: block.hash });
      return { p, url, attempts, blockNumber: b, block };
    } catch (e) { attempts.push({ url, ok: false, error: String(e) }); }
  }
  throw new Error(JSON.stringify(attempts));
}
function slotAddress(raw) {
  if (!raw || raw === '0x' || /^0x0+$/.test(raw)) return ethers.constants.AddressZero;
  return ethers.utils.getAddress(`0x${raw.slice(-40)}`);
}
async function identity(p, address, blockTag) {
  const [code, nativeBalance, impl, admin] = await Promise.all([
    p.getCode(address, blockTag), p.getBalance(address, blockTag),
    p.getStorageAt(address, IMPLEMENTATION_SLOT, blockTag), p.getStorageAt(address, ADMIN_SLOT, blockTag),
  ]);
  return {
    address, codeBytes: (code.length - 2) / 2, codeHash: ethers.utils.keccak256(code),
    nativeBalanceWei: nativeBalance.toString(), implementationRaw: impl, implementation: slotAddress(impl),
    adminRaw: admin, admin: slotAddress(admin),
  };
}
function items(body) {
  if (Array.isArray(body)) return body;
  if (body && Array.isArray(body.items)) return body.items;
  return [];
}
function itemAddress(item) {
  const t = item?.token || item || {};
  const a = t.address_hash || t.address || t.contract_address_hash;
  try { return a ? ethers.utils.getAddress(a) : null; } catch { return null; }
}
function itemBalance(item) {
  const x = item?.value ?? item?.balance ?? item?.token_balance;
  try { return x == null ? null : ethers.BigNumber.from(String(x)); } catch { return null; }
}
async function tokenState(p, tokenAddress, holder, blockTag, item) {
  const c = new ethers.Contract(tokenAddress, erc20Abi, p);
  const [balance, decimals, symbol, name, supply] = await Promise.all([
    safe(c.balanceOf(holder, { blockTag })), safe(c.decimals({ blockTag })),
    safe(c.symbol({ blockTag })), safe(c.name({ blockTag })), safe(c.totalSupply({ blockTag })),
  ]);
  const meta = item?.token || item || {};
  const dec = decimals.ok ? Number(decimals.value) : (meta.decimals == null ? null : Number(meta.decimals));
  const formatted = balance.ok && dec != null ? ethers.utils.formatUnits(balance.value, dec) : null;
  const exchangeRate = meta.exchange_rate == null ? null : Number(meta.exchange_rate);
  const usd = formatted != null && Number.isFinite(exchangeRate) ? Number(formatted) * exchangeRate : null;
  return {
    tokenAddress, balance, decimals, symbol, name, supply, formattedBalance: formatted,
    indexerBalance: itemBalance(item)?.toString() || null,
    indexerMetadata: { symbol: meta.symbol || null, name: meta.name || null, decimals: meta.decimals || null, exchangeRate: meta.exchange_rate || null, type: meta.type || null, reputation: meta.reputation || null },
    estimatedUsd: usd,
  };
}
async function addressState(p, address, blockTag) {
  const endpointResults = {};
  for (const [key, path] of Object.entries({
    info: `/api/v2/addresses/${address}`,
    balances: `/api/v2/addresses/${address}/token-balances`,
    tokens: `/api/v2/addresses/${address}/tokens?type=ERC-20`,
    transfers: `/api/v2/addresses/${address}/token-transfers?type=ERC-20`,
  })) endpointResults[key] = await safe(getJson(`${BLOCKSCOUT}${path}`));
  const map = new Map();
  for (const key of ['balances', 'tokens']) {
    if (!endpointResults[key].ok) continue;
    for (const item of items(endpointResults[key].value)) {
      const a = itemAddress(item);
      if (a) map.set(a.toLowerCase(), item);
    }
  }
  const tokens = [];
  for (const [a, item] of map) {
    const bal = itemBalance(item);
    if (bal && bal.isZero()) continue;
    tokens.push(await tokenState(p, ethers.utils.getAddress(a), address, blockTag, item));
  }
  return { identity: await identity(p, address, blockTag), endpointResults, tokens };
}

(async () => {
  fs.mkdirSync(OUT, { recursive: true });
  const { p, url, attempts, blockNumber, block } = await provider();
  const a = new ethers.Contract(addresses.routerA, routerAAbi, p);
  const b = new ethers.Contract(addresses.routerB, routerBAbi, p);
  const r = new ethers.Contract(addresses.registry, registryAbi, p);
  const [routerAState, routerBState, componentIdentity, registryIdentity, calls, stats] = await Promise.all([
    addressState(p, addresses.routerA, blockNumber),
    addressState(p, addresses.routerB, blockNumber),
    identity(p, addresses.component, blockNumber),
    identity(p, addresses.registry, blockNumber),
    Promise.all([
      safe(a.owner({ blockTag: blockNumber })), safe(a.paused({ blockTag: blockNumber })),
      safe(a.adapterWhitelist(addresses.component, { blockTag: blockNumber })),
      safe(b.owner({ blockTag: blockNumber })), safe(b.paused({ blockTag: blockNumber })),
      safe(b.adapterWhitelist(addresses.component, { blockTag: blockNumber })),
      safe(b.whitelistManager({ blockTag: blockNumber })), safe(b.defaultWhitelistModule({ blockTag: blockNumber })),
      safe(r.isWhitelisted(addresses.component, 0, { blockTag: blockNumber })), safe(r.owner({ blockTag: blockNumber })),
    ]),
    safe(getJson(`${BLOCKSCOUT}/api/v2/stats`)),
  ]);
  const callNames = ['routerA.owner','routerA.paused','routerA.componentAllowed','routerB.owner','routerB.paused','routerB.legacyComponentAllowed','routerB.registry','routerB.defaultModule','registry.componentAllowed','registry.owner'];
  const callMap = Object.fromEntries(callNames.map((name, i) => [name, calls[i]]));
  const result = {
    generatedAt: new Date().toISOString(), scope: 'read-only', addresses,
    chain: { rpc: url, attempts, chainId: EXPECTED_CHAIN_ID, blockNumber, blockHash: block.hash, timestamp: block.timestamp },
    identities: { routerA: routerAState.identity, routerB: routerBState.identity, component: componentIdentity, registry: registryIdentity },
    calls: callMap, routerA: routerAState, routerB: routerBState, stats,
  };
  fs.writeFileSync(`${OUT}/state.json`, JSON.stringify(result, null, 2));
  fs.writeFileSync(`${OUT}/block.txt`, `${blockNumber}\n${block.hash}\n${block.timestamp}\n`);
  console.log(JSON.stringify({ chain: result.chain, calls: callMap, tokenCounts: { routerA: routerAState.tokens.length, routerB: routerBState.tokens.length } }, null, 2));
})().catch(e => {
  fs.mkdirSync(OUT, { recursive: true });
  fs.writeFileSync(`${OUT}/error.txt`, String(e && e.stack ? e.stack : e));
  console.error(e);
  process.exit(1);
});
