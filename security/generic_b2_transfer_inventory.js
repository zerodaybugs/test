'use strict';

const fs = require('fs');
const { ethers } = require('ethers');

const OUT = 'b2-transfer-output';
const CHAIN_ID = 223;
const START_BLOCK = 30415006;
const ROUTERS = {
  routerA: ethers.utils.getAddress('0x3cb5fa87703c7165cc5f2087B3e80b58fb6d8CE8'),
  routerB: ethers.utils.getAddress('0x830fBad7Cd1c3Cc5B693Dc64b985f2901B253C5B'),
};
const RPCS = [
  'https://rpc.bsquared.network',
  'https://mainnet.b2-rpc.com',
  'https://b2-mainnet.alt.technology',
  'https://b2-mainnet-public.s.chainbase.com',
  'https://rpc.ankr.com/b2',
  'https://223.rpc.thirdweb.com',
];
const TRANSFER_TOPIC = ethers.utils.id('Transfer(address,address,uint256)');
const PADDED_ROUTERS = Object.values(ROUTERS).map((x) => ethers.utils.hexZeroPad(x, 32));
const erc20Abi = [
  'function balanceOf(address) view returns(uint256)',
  'function decimals() view returns(uint8)',
  'function symbol() view returns(string)',
  'function name() view returns(string)',
  'function totalSupply() view returns(uint256)',
];

function ser(value) {
  if (ethers.BigNumber.isBigNumber(value)) return value.toString();
  if (Array.isArray(value)) return value.map(ser);
  if (value && typeof value === 'object') {
    const out = {};
    for (const [key, item] of Object.entries(value)) {
      if (!/^\d+$/.test(key)) out[key] = ser(item);
    }
    return out;
  }
  return value;
}

async function safe(promise) {
  try { return { ok: true, value: ser(await promise) }; }
  catch (error) { return { ok: false, error: String(error && error.stack ? error.stack : error) }; }
}

async function providers() {
  const attempts = [];
  const working = [];
  for (const url of RPCS) {
    try {
      const provider = new ethers.providers.StaticJsonRpcProvider(url, { chainId: CHAIN_ID, name: 'b2' });
      const [network, blockNumber] = await Promise.all([provider.getNetwork(), provider.getBlockNumber()]);
      if (network.chainId !== CHAIN_ID) throw new Error(`wrong chain ${network.chainId}`);
      const block = await provider.getBlock(blockNumber);
      working.push({ url, provider, blockNumber, blockHash: block.hash });
      attempts.push({ url, ok: true, chainId: network.chainId, blockNumber, blockHash: block.hash });
    } catch (error) {
      attempts.push({ url, ok: false, error: String(error) });
    }
  }
  if (!working.length) throw new Error(`no working RPC: ${JSON.stringify(attempts)}`);
  const blockNumber = Math.min(...working.map((x) => x.blockNumber));
  const stateProvider = working[0].provider;
  const block = await stateProvider.getBlock(blockNumber);
  return { working, attempts, stateProvider, blockNumber, block };
}

async function queryRange(working, filter) {
  const attempts = [];
  for (const endpoint of working) {
    try {
      const logs = await endpoint.provider.getLogs(filter);
      attempts.push({ url: endpoint.url, ok: true, count: logs.length });
      return { logs, rpc: endpoint.url, attempts };
    } catch (error) {
      attempts.push({ url: endpoint.url, ok: false, error: String(error) });
    }
  }
  const error = new Error('all RPC endpoints rejected eth_getLogs range');
  error.attempts = attempts;
  throw error;
}

async function scan(working, fromBlock, toBlock, topics, label) {
  let current = fromBlock;
  let span = 50000;
  const minSpan = 100;
  const logs = [];
  const progress = [];
  while (current <= toBlock) {
    const end = Math.min(toBlock, current + span - 1);
    try {
      const result = await queryRange(working, { fromBlock: current, toBlock: end, topics });
      logs.push(...result.logs);
      progress.push({ label, fromBlock: current, toBlock: end, span, count: result.logs.length, rpc: result.rpc, attempts: result.attempts });
      current = end + 1;
      if (result.logs.length < 250 && span < 200000) span = Math.min(200000, span * 2);
    } catch (error) {
      progress.push({ label, fromBlock: current, toBlock: end, span, error: String(error), attempts: error.attempts || null });
      if (span <= minSpan) throw error;
      span = Math.max(minSpan, Math.floor(span / 2));
    }
  }
  return { logs, progress };
}

function topicAddress(topic) {
  if (!topic || topic.length !== 66) return null;
  try { return ethers.utils.getAddress(`0x${topic.slice(-40)}`); }
  catch { return null; }
}

function addToken(map, log, direction) {
  const token = ethers.utils.getAddress(log.address);
  const key = token.toLowerCase();
  const row = map.get(key) || {
    token,
    firstBlock: log.blockNumber,
    lastBlock: log.blockNumber,
    inboundLogs: 0,
    outboundLogs: 0,
    sampleTxs: [],
    counterparties: new Set(),
  };
  row.firstBlock = Math.min(row.firstBlock, log.blockNumber);
  row.lastBlock = Math.max(row.lastBlock, log.blockNumber);
  row[direction === 'inbound' ? 'inboundLogs' : 'outboundLogs'] += 1;
  if (row.sampleTxs.length < 10) row.sampleTxs.push(log.transactionHash);
  const from = topicAddress(log.topics[1]);
  const to = topicAddress(log.topics[2]);
  for (const value of [from, to]) {
    if (value && !Object.values(ROUTERS).some((r) => r.toLowerCase() === value.toLowerCase()) && row.counterparties.size < 100) {
      row.counterparties.add(value);
    }
  }
  map.set(key, row);
}

async function inspectToken(provider, blockTag, row) {
  const code = await provider.getCode(row.token, blockTag);
  const token = new ethers.Contract(row.token, erc20Abi, provider);
  const [balanceA, balanceB, decimals, symbol, name, totalSupply] = await Promise.all([
    safe(token.balanceOf(ROUTERS.routerA, { blockTag })),
    safe(token.balanceOf(ROUTERS.routerB, { blockTag })),
    safe(token.decimals({ blockTag })),
    safe(token.symbol({ blockTag })),
    safe(token.name({ blockTag })),
    safe(token.totalSupply({ blockTag })),
  ]);
  const isErc20Like = balanceA.ok && balanceB.ok && decimals.ok;
  const dec = decimals.ok ? Number(decimals.value) : null;
  const formattedA = balanceA.ok && dec != null ? ethers.utils.formatUnits(balanceA.value, dec) : null;
  const formattedB = balanceB.ok && dec != null ? ethers.utils.formatUnits(balanceB.value, dec) : null;
  return {
    token: row.token,
    codeBytes: Math.max((code.length - 2) / 2, 0),
    codeHash: ethers.utils.keccak256(code),
    firstBlock: row.firstBlock,
    lastBlock: row.lastBlock,
    inboundLogs: row.inboundLogs,
    outboundLogs: row.outboundLogs,
    sampleTxs: row.sampleTxs,
    counterparties: [...row.counterparties],
    isErc20Like,
    balanceA,
    balanceB,
    decimals,
    symbol,
    name,
    totalSupply,
    formattedBalanceA: formattedA,
    formattedBalanceB: formattedB,
    nonzeroA: balanceA.ok && !ethers.BigNumber.from(balanceA.value).isZero(),
    nonzeroB: balanceB.ok && !ethers.BigNumber.from(balanceB.value).isZero(),
  };
}

async function mapLimit(items, limit, fn) {
  const out = new Array(items.length);
  let next = 0;
  async function worker() {
    while (true) {
      const index = next++;
      if (index >= items.length) return;
      out[index] = await fn(items[index], index);
    }
  }
  await Promise.all(Array.from({ length: Math.min(limit, items.length || 1) }, worker));
  return out;
}

(async () => {
  fs.mkdirSync(OUT, { recursive: true });
  const { working, attempts, stateProvider, blockNumber, block } = await providers();
  const outbound = await scan(
    working,
    START_BLOCK,
    blockNumber,
    [TRANSFER_TOPIC, PADDED_ROUTERS],
    'outbound'
  );
  const inbound = await scan(
    working,
    START_BLOCK,
    blockNumber,
    [TRANSFER_TOPIC, null, PADDED_ROUTERS],
    'inbound'
  );

  const dedup = new Map();
  for (const [direction, collection] of [['outbound', outbound.logs], ['inbound', inbound.logs]]) {
    for (const log of collection) {
      if (!log.topics || log.topics.length < 3 || log.data.length !== 66) continue;
      const key = `${log.transactionHash}-${log.logIndex}`;
      if (!dedup.has(key)) dedup.set(key, { log, direction });
    }
  }

  const tokenMap = new Map();
  for (const { log, direction } of dedup.values()) addToken(tokenMap, log, direction);
  const tokenRows = [...tokenMap.values()].sort((a, b) => a.firstBlock - b.firstBlock);
  const inspected = await mapLimit(tokenRows, 5, (row) => inspectToken(stateProvider, blockNumber, row));
  const nonzero = inspected.filter((x) => x.nonzeroA || x.nonzeroB);
  const [nativeA, nativeB] = await Promise.all([
    stateProvider.getBalance(ROUTERS.routerA, blockNumber),
    stateProvider.getBalance(ROUTERS.routerB, blockNumber),
  ]);

  const result = {
    generatedAt: new Date().toISOString(),
    scope: 'READ-ONLY. No transaction signed or broadcast.',
    chain: {
      chainId: CHAIN_ID,
      blockNumber,
      blockHash: block.hash,
      timestamp: block.timestamp,
      startBlock: START_BLOCK,
      rpcAttempts: attempts,
    },
    routers: ROUTERS,
    scans: {
      outbound: { logCount: outbound.logs.length, progress: outbound.progress },
      inbound: { logCount: inbound.logs.length, progress: inbound.progress },
      deduplicatedTransferCount: dedup.size,
    },
    nativeBalancesWei: { routerA: nativeA.toString(), routerB: nativeB.toString() },
    tokenCount: inspected.length,
    nonzeroTokenCount: nonzero.length,
    nonzeroTokens: nonzero,
    allTokens: inspected,
  };

  fs.writeFileSync(`${OUT}/transfer-inventory.json`, JSON.stringify(result, null, 2));
  fs.writeFileSync(`${OUT}/block.txt`, `${blockNumber}\n${block.hash}\n${block.timestamp}\n`);
  fs.writeFileSync(`${OUT}/summary.json`, JSON.stringify({
    chain: result.chain,
    scans: {
      outboundLogCount: result.scans.outbound.logCount,
      inboundLogCount: result.scans.inbound.logCount,
      deduplicatedTransferCount: result.scans.deduplicatedTransferCount,
    },
    nativeBalancesWei: result.nativeBalancesWei,
    tokenCount: result.tokenCount,
    nonzeroTokenCount: result.nonzeroTokenCount,
    nonzeroTokens: nonzero.map((x) => ({
      token: x.token,
      symbol: x.symbol,
      formattedBalanceA: x.formattedBalanceA,
      formattedBalanceB: x.formattedBalanceB,
    })),
  }, null, 2));
  console.log(fs.readFileSync(`${OUT}/summary.json`, 'utf8'));
})().catch((error) => {
  fs.mkdirSync(OUT, { recursive: true });
  const message = String(error && error.stack ? error.stack : error);
  fs.writeFileSync(`${OUT}/error.txt`, message);
  console.error(message);
  process.exit(1);
});
