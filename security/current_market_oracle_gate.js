'use strict';
const fs = require('fs');
const { ethers } = require('ethers');
const sdk = require('@defillama/sdk');

const LABEL = process.env.LABEL;
const CHAIN = process.env.CHAIN;
const RPCS = process.env.RPCS.split(',').map(x => x.trim()).filter(Boolean);
const FACTORIES = process.env.FACTORIES.split(',').map(x => {
  const [address, fromBlock] = x.split(':');
  return { address: ethers.utils.getAddress(address), fromBlock: Number(fromBlock) };
});
const OUT = `current-market-oracle-${LABEL}`;
const MARKET_TOPIC = '0x3f544a0e66146e1c515b04e3d00d07fabc299aa08db26f13ae0a2e3797503286';
const ORDER_TOPIC = ethers.utils.id('CreateOrder(address,address)');
const ZERO = ethers.constants.AddressZero;

const marketAbi = [
  'function name() view returns(string)',
  'function tokens() view returns(address ft,address xt,address gt,address collateral,address debtToken)',
  'function config() view returns(tuple(address treasurer,uint64 maturity,tuple(uint32 lendTakerFeeRatio,uint32 lendMakerFeeRatio,uint32 borrowTakerFeeRatio,uint32 borrowMakerFeeRatio,uint32 mintGtFeeRatio,uint32 mintGtFeeRef) feeConfig))'
];
const gtAbi = [
  'function getGtConfig() view returns(tuple(address collateral,address debtToken,address ft,address treasurer,uint64 maturity,tuple(address oracle,uint32 liquidationLtv,uint32 maxLtv,bool liquidatable) loanConfig))',
  'function totalSupply() view returns(uint256)',
  'function collateralCapacity() view returns(uint256)'
];
const orderAbi = [
  'function tokenReserves() view returns(uint256 ftReserve,uint256 xtReserve)',
  'function getRealReserves() view returns(uint256 ftReserve,uint256 xtReserve)',
  'function pool() view returns(address)',
  'function virtualXtReserve() view returns(uint256)',
  'function orderExpiryTimestamp() view returns(uint64)'
];
const tokenAbi = [
  'function symbol() view returns(string)', 'function decimals() view returns(uint8)',
  'function totalSupply() view returns(uint256)', 'function balanceOf(address) view returns(uint256)'
];
const poolAbi = [
  'function asset() view returns(address)', 'function totalAssets() view returns(uint256)',
  'function balanceOf(address) view returns(uint256)', 'function convertToAssets(uint256) view returns(uint256)'
];
const oracleV2Abi = [
  'function getPrice(address) view returns(uint256 price,uint8 decimals)',
  'function oracles(address) view returns(address aggregator,address backupAggregator,int256 maxPrice,int256 minPrice,uint32 heartbeat,uint32 backupHeartbeat)'
];
const oracleV1Abi = [
  'function getPrice(address) view returns(uint256 price,uint8 decimals)',
  'function oracles(address) view returns(address aggregator,address backupAggregator,uint32 heartbeat)'
];
const feedAbi = [
  'function latestRoundData() view returns(uint80 roundId,int256 answer,uint256 startedAt,uint256 updatedAt,uint80 answeredInRound)',
  'function latestAnswer() view returns(int256)', 'function latestTimestamp() view returns(uint256)',
  'function decimals() view returns(uint8)', 'function description() view returns(string)',
  'function pool() view returns(address)', 'function twapPeriod() view returns(uint32)',
  'function baseToken() view returns(address)', 'function quoteToken() view returns(address)',
  'function asset() view returns(address)', 'function PRICE_FEED() view returns(address)',
  'function MARKET() view returns(address)', 'function DURATION() view returns(uint32)',
  'function aTokenToBTokenPriceFeed() view returns(address)', 'function bTokenToCTokenPriceFeed() view returns(address)',
  'function uspcOracle() view returns(address)', 'function xaueOracle() view returns(address)',
  'function pharosOracle() view returns(address)', 'function ondoOracle() view returns(address)',
  'function dusdOracle() view returns(address)', 'function result() view returns(uint256)'
];

function ser(v) {
  if (ethers.BigNumber.isBigNumber(v)) return v.toString();
  if (Array.isArray(v)) return v.map(ser);
  if (v && typeof v === 'object') {
    const out = {};
    for (const [k, x] of Object.entries(v)) if (!/^\d+$/.test(k)) out[k] = ser(x);
    return out;
  }
  return v;
}
async function safe(p) { try { return { ok: true, value: ser(await p) }; } catch (e) { return { ok: false, error: String(e) }; } }
function addrTopic(topic) { return ethers.utils.getAddress('0x' + topic.slice(-40)); }
function normalize(log) {
  return {
    topics: log.topics || [log.topic0, log.topic1, log.topic2, log.topic3].filter(Boolean),
    blockNumber: Number(log.blockNumber || log.block_number || 0),
    transactionHash: log.transactionHash || log.transaction_hash || ''
  };
}
async function discover() {
  const attempts = [], providers = [];
  for (const url of RPCS) {
    try {
      const p = new ethers.providers.JsonRpcProvider(url);
      const [network, block] = await Promise.all([p.getNetwork(), p.getBlockNumber()]);
      attempts.push({ url, ok: true, chainId: network.chainId, block });
      providers.push({ p, url, chainId: network.chainId, block });
    } catch (e) { attempts.push({ url, ok: false, error: String(e) }); }
  }
  if (!providers.length) throw new Error(`No usable RPC: ${JSON.stringify(attempts)}`);
  const chainId = providers[0].chainId;
  return { providers: providers.filter(x => x.chainId === chainId), attempts };
}
async function directLogs(providers, address, fromBlock, toBlock, topic0) {
  const attempts = [];
  for (const endpoint of providers) {
    let current = fromBlock, span = 100000, logs = [];
    try {
      while (current <= toBlock) {
        const end = Math.min(toBlock, current + span - 1);
        try {
          const part = await endpoint.p.getLogs({ address, fromBlock: current, toBlock: end, topics: [topic0] });
          logs.push(...part); current = end + 1;
          if (part.length < 100 && span < 500000) span = Math.min(500000, span * 2);
        } catch (e) {
          if (span <= 100) throw e;
          span = Math.max(100, Math.floor(span / 2));
        }
      }
      attempts.push({ source: endpoint.url, ok: true, count: logs.length });
      return { logs: logs.map(normalize), source: endpoint.url, attempts };
    } catch (e) { attempts.push({ source: endpoint.url, ok: false, error: String(e) }); }
  }
  return { logs: [], source: null, attempts, error: 'all RPC log scans failed' };
}
async function logs(providers, address, fromBlock, toBlock, topic0) {
  const direct = await directLogs(providers, address, fromBlock, toBlock, topic0);
  if (!direct.error) return direct;
  try {
    const result = await sdk.api.util.getLogs({ chain: CHAIN, target: address, topic: topic0, fromBlock, toBlock });
    const indexed = (result.output || []).map(normalize);
    return { logs: indexed, source: 'defillama-indexer', attempts: direct.attempts.concat([{ source: 'defillama', ok: true, count: indexed.length }]) };
  } catch (e) {
    return { logs: [], source: null, attempts: direct.attempts.concat([{ source: 'defillama', ok: false, error: String(e) }]), error: 'all log sources failed' };
  }
}
async function feedInfo(p, address, blockTag) {
  if (!address || address === ZERO) return null;
  const c = new ethers.Contract(address, feedAbi, p);
  const code = await p.getCode(address, blockTag);
  const getters = {};
  for (const key of ['pool','twapPeriod','baseToken','quoteToken','asset','PRICE_FEED','MARKET','DURATION','aTokenToBTokenPriceFeed','bTokenToCTokenPriceFeed','uspcOracle','xaueOracle','pharosOracle','ondoOracle','dusdOracle','result']) {
    getters[key] = await safe(c[key]({ blockTag }));
  }
  return ser({ address, codeBytes: Math.max((code.length - 2) / 2, 0), codeHash: ethers.utils.keccak256(code),
    round: await safe(c.latestRoundData({ blockTag })), latestAnswer: await safe(c.latestAnswer({ blockTag })),
    latestTimestamp: await safe(c.latestTimestamp({ blockTag })), decimals: await safe(c.decimals({ blockTag })),
    description: await safe(c.description({ blockTag })), getters });
}
async function oracleInfo(p, address, asset, blockTag) {
  const v2 = new ethers.Contract(address, oracleV2Abi, p);
  const c2 = await safe(v2.oracles(asset, { blockTag }));
  if (c2.ok) {
    return ser({ shape: 'V2', address, asset, config: c2, current: await safe(v2.getPrice(asset, { blockTag })),
      primary: await feedInfo(p, c2.value.aggregator, blockTag), backup: await feedInfo(p, c2.value.backupAggregator, blockTag) });
  }
  const v1 = new ethers.Contract(address, oracleV1Abi, p);
  const c1 = await safe(v1.oracles(asset, { blockTag }));
  return ser({ shape: c1.ok ? 'V1' : 'unknown', address, asset, config: c1, current: await safe(v1.getPrice(asset, { blockTag })),
    primary: c1.ok ? await feedInfo(p, c1.value.aggregator, blockTag) : null,
    backup: c1.ok ? await feedInfo(p, c1.value.backupAggregator, blockTag) : null });
}
async function orderInfo(p, order, blockTag) {
  const c = new ethers.Contract(order, orderAbi, p);
  const [reserves, real, pool, virtualXtReserve, expiry, code] = await Promise.all([
    safe(c.tokenReserves({ blockTag })), safe(c.getRealReserves({ blockTag })), safe(c.pool({ blockTag })),
    safe(c.virtualXtReserve({ blockTag })), safe(c.orderExpiryTimestamp({ blockTag })), p.getCode(order, blockTag)
  ]);
  let poolState = null;
  if (pool.ok && pool.value !== ZERO) {
    const pc = new ethers.Contract(pool.value, poolAbi, p);
    const [asset, totalAssets, shares] = await Promise.all([safe(pc.asset({ blockTag })), safe(pc.totalAssets({ blockTag })), safe(pc.balanceOf(order, { blockTag }))]);
    const assets = shares.ok ? await safe(pc.convertToAssets(shares.value, { blockTag })) : null;
    poolState = { address: pool.value, asset, totalAssets, shares, orderAssets: assets };
  }
  return ser({ address: order, codeHash: ethers.utils.keccak256(code), reserves, realReserves: real, virtualXtReserve, expiry, pool: poolState });
}

(async () => {
  fs.mkdirSync(OUT, { recursive: true });
  const { providers, attempts } = await discover();
  const p = providers[0].p;
  const blockNumber = Math.min(...providers.map(x => x.block));
  const block = await p.getBlock(blockNumber);
  const map = new Map(), factoryScans = [];
  for (const factory of FACTORIES) {
    const scan = await logs(providers, factory.address, factory.fromBlock, blockNumber, MARKET_TOPIC);
    factoryScans.push({ factory, source: scan.source, count: scan.logs.length, attempts: scan.attempts, error: scan.error || null });
    for (const log of scan.logs) {
      if (log.topics.length < 4) continue;
      const market = addrTopic(log.topics[1]);
      map.set(market.toLowerCase(), { market, factory: factory.address, createdBlock: log.blockNumber, createdTx: log.transactionHash,
        collateralEvent: addrTopic(log.topics[2]), debtEvent: addrTopic(log.topics[3]) });
    }
  }
  const markets = [];
  for (const base of map.values()) {
    try {
      const market = new ethers.Contract(base.market, marketAbi, p);
      const [name, tokens, config, code] = await Promise.all([safe(market.name({ blockTag: blockNumber })), market.tokens({ blockTag: blockNumber }), market.config({ blockTag: blockNumber }), p.getCode(base.market, blockNumber)]);
      const ft = new ethers.Contract(tokens.ft, tokenAbi, p), xt = new ethers.Contract(tokens.xt, tokenAbi, p), gt = new ethers.Contract(tokens.gt, gtAbi, p), debt = new ethers.Contract(tokens.debtToken, tokenAbi, p), collateral = new ethers.Contract(tokens.collateral, tokenAbi, p);
      const [gtConfig, ftSupply, xtSupply, gtSupply, debtMarketBalance, collateralGtBalance, debtSymbol, debtDecimals, collateralSymbol, collateralDecimals, capacity] = await Promise.all([
        gt.getGtConfig({ blockTag: blockNumber }), ft.totalSupply({ blockTag: blockNumber }), xt.totalSupply({ blockTag: blockNumber }), gt.totalSupply({ blockTag: blockNumber }),
        debt.balanceOf(base.market, { blockTag: blockNumber }), collateral.balanceOf(tokens.gt, { blockTag: blockNumber }),
        safe(debt.symbol({ blockTag: blockNumber })), safe(debt.decimals({ blockTag: blockNumber })), safe(collateral.symbol({ blockTag: blockNumber })), safe(collateral.decimals({ blockTag: blockNumber })), safe(gt.collateralCapacity({ blockTag: blockNumber }))
      ]);
      const [debtOracle, collateralOracle] = await Promise.all([
        oracleInfo(p, gtConfig.loanConfig.oracle, tokens.debtToken, blockNumber),
        oracleInfo(p, gtConfig.loanConfig.oracle, tokens.collateral, blockNumber)
      ]);
      const orderScan = await logs(providers, base.market, base.createdBlock, blockNumber, ORDER_TOPIC);
      const orders = [];
      for (const log of orderScan.logs) if (log.topics.length >= 3) orders.push(await orderInfo(p, addrTopic(log.topics[2]), blockNumber));
      const orderFt = orders.reduce((sum, o) => {
        try { return o.reserves.ok ? sum.add(o.reserves.value.ftReserve) : sum; } catch { return sum; }
      }, ethers.constants.Zero);
      const poolAssets = orders.reduce((sum, o) => {
        try { return o.pool?.orderAssets?.ok ? sum.add(o.pool.orderAssets.value) : sum; } catch { return sum; }
      }, ethers.constants.Zero);
      const debtMinZero = debtOracle.shape === 'V2' && debtOracle.config.ok && String(debtOracle.config.value.minPrice) === '0';
      const collateralMinZero = collateralOracle.shape === 'V2' && collateralOracle.config.ok && String(collateralOracle.config.value.minPrice) === '0';
      const gates = {
        active: Number(config.maturity) > block.timestamp,
        debtMinZero, collateralMinZero,
        debtCurrentZero: debtOracle.current.ok && String(debtOracle.current.value.price || debtOracle.current.value[0] || '') === '0',
        nonzeroFt: !ftSupply.isZero(), nonzeroGt: !gtSupply.isZero(), orderCount: orders.length,
        orderFtReserve: orderFt.toString(), orderPoolAssets: poolAssets.toString(), debtMarketBalance: debtMarketBalance.toString()
      };
      markets.push(ser({ ...base, codeHash: ethers.utils.keccak256(code), name, config, tokens,
        metadata: { debtSymbol, debtDecimals, collateralSymbol, collateralDecimals },
        balances: { ftSupply, xtSupply, gtSupply, debtMarketBalance, collateralGtBalance, collateralCapacity: capacity, orderFtReserve: orderFt, orderPoolAssets: poolAssets },
        gtConfig, debtOracle, collateralOracle, orderScan: { source: orderScan.source, count: orderScan.logs.length, attempts: orderScan.attempts }, orders, gates }));
    } catch (e) { markets.push({ ...base, fatalError: String(e && e.stack ? e.stack : e) }); }
  }
  const candidates = markets.filter(m => m.gates?.active && (m.gates.debtMinZero || m.gates.collateralMinZero) && (m.gates.nonzeroFt || m.gates.nonzeroGt || m.gates.orderCount > 0));
  const result = { generatedAt: new Date().toISOString(), scope: 'READ_ONLY_NO_TRANSACTIONS', label: LABEL, chain: CHAIN,
    rpcAttempts: attempts, snapshot: { blockNumber, blockHash: block.hash, timestamp: block.timestamp }, factoryScans,
    marketCount: markets.length, candidateCount: candidates.length, candidates, markets };
  fs.writeFileSync(`${OUT}/inventory.json`, JSON.stringify(result, null, 2));
  fs.writeFileSync(`${OUT}/summary.json`, JSON.stringify({ label: LABEL, chain: CHAIN, snapshot: result.snapshot, marketCount: markets.length, candidateCount: candidates.length,
    candidates: candidates.map(m => ({ market: m.market, name: m.name, metadata: m.metadata, balances: m.balances, gates: m.gates, debtOracle: m.debtOracle, collateralOracle: m.collateralOracle })) }, null, 2));
  console.log(fs.readFileSync(`${OUT}/summary.json`, 'utf8'));
})().catch(e => { fs.mkdirSync(OUT, { recursive: true }); fs.writeFileSync(`${OUT}/error.txt`, String(e && e.stack ? e.stack : e)); console.error(e); process.exit(1); });
