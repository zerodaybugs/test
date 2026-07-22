'use strict';

const fs = require('fs');
const { ethers } = require('ethers');

const LABEL = process.env.LABEL;
const RPCS = process.env.RPCS.split(',').map(x => x.trim()).filter(Boolean);
const FACTORIES = process.env.FACTORIES.split(',').map(x => {
  const [address, fromBlock] = x.split(':');
  return { address: ethers.utils.getAddress(address), fromBlock: Number(fromBlock) };
});
const OUT = `termmax-postaudit-${LABEL}`;
const MARKET_TOPIC = '0x3f544a0e66146e1c515b04e3d00d07fabc299aa08db26f13ae0a2e3797503286';
const CREATE_ORDER_TOPIC = ethers.utils.id('CreateOrder(address,address)');

const marketAbi = [
  'function name() view returns(string)',
  'function isOpen() view returns(bool)',
  'function tokens() view returns(address ft,address xt,address gt,address collateral,address debtToken)',
  'function config() view returns(tuple(address treasurer,uint64 maturity,tuple(uint32 lendTakerFeeRatio,uint32 lendMakerFeeRatio,uint32 borrowTakerFeeRatio,uint32 borrowMakerFeeRatio,uint32 mintGtFeeRatio,uint32 mintGtFeeRef) feeConfig))'
];
const gtAbi = [
  'function getGtConfig() view returns(tuple(address collateral,address debtToken,address ft,address treasurer,uint64 maturity,tuple(address oracle,uint32 liquidationLtv,uint32 maxLtv,bool liquidatable) loanConfig))',
  'function totalSupply() view returns(uint256)'
];
const erc20Abi = [
  'function symbol() view returns(string)', 'function name() view returns(string)',
  'function decimals() view returns(uint8)', 'function totalSupply() view returns(uint256)',
  'function balanceOf(address) view returns(uint256)'
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
  'function decimals() view returns(uint8)', 'function description() view returns(string)', 'function version() view returns(uint256)',
  'function pool() view returns(address)', 'function twapPeriod() view returns(uint32)',
  'function baseToken() view returns(address)', 'function quoteToken() view returns(address)', 'function asset() view returns(address)',
  'function PRICE_FEED() view returns(address)', 'function MARKET() view returns(address)', 'function DURATION() view returns(uint32)',
  'function aTokenToBTokenPriceFeed() view returns(address)', 'function bTokenToCTokenPriceFeed() view returns(address)',
  'function dusdOracle() view returns(address)', 'function uspcOracle() view returns(address)',
  'function xaueOracle() view returns(address)', 'function pharosOracle() view returns(address)', 'function ondoOracle() view returns(address)',
  'function result() view returns(uint256)', 'function pairIndex() view returns(uint256)'
];
const orderAbi = [
  'function tokenReserves() view returns(uint256 ftReserve,uint256 xtReserve)',
  'function orderExpiryTimestamp() view returns(uint64)',
  'function paused() view returns(bool)',
  'function pool() view returns(address)',
  'function virtualXtReserve() view returns(uint256)'
];

function ser(x) {
  if (ethers.BigNumber.isBigNumber(x)) return x.toString();
  if (Array.isArray(x)) return x.map(ser);
  if (x && typeof x === 'object') {
    const o = {};
    for (const [k, v] of Object.entries(x)) if (!/^\d+$/.test(k)) o[k] = ser(v);
    return o;
  }
  return x;
}
async function safe(p) {
  try { return { ok: true, value: ser(await p) }; }
  catch (e) { return { ok: false, error: String(e && e.stack ? e.stack : e) }; }
}
function topicAddress(topic) { return ethers.utils.getAddress(`0x${topic.slice(-40)}`); }

async function providers() {
  const attempts = [], working = [];
  for (const url of RPCS) {
    try {
      const provider = new ethers.providers.JsonRpcProvider(url);
      const [network, block] = await Promise.all([provider.getNetwork(), provider.getBlockNumber()]);
      attempts.push({ url, ok: true, chainId: network.chainId, block });
      working.push({ url, provider, chainId: network.chainId, block });
    } catch (e) { attempts.push({ url, ok: false, error: String(e) }); }
  }
  if (!working.length) throw new Error(`No working RPC: ${JSON.stringify(attempts)}`);
  const chainId = working[0].chainId;
  const same = working.filter(x => x.chainId === chainId);
  const blockNumber = Math.min(...same.map(x => x.block));
  const block = await same[0].provider.getBlock(blockNumber);
  return { working: same, provider: same[0].provider, chainId, blockNumber, block, attempts };
}

async function logsAdaptive(working, address, fromBlock, toBlock, topics) {
  let current = fromBlock, span = 100000;
  const logs = [], progress = [];
  while (current <= toBlock) {
    const end = Math.min(toBlock, current + span - 1);
    let result = null;
    const tries = [];
    for (const endpoint of working) {
      try {
        const part = await endpoint.provider.getLogs({ address, fromBlock: current, toBlock: end, topics });
        tries.push({ url: endpoint.url, ok: true, count: part.length });
        result = { part, url: endpoint.url };
        break;
      } catch (e) { tries.push({ url: endpoint.url, ok: false, error: String(e) }); }
    }
    if (result) {
      logs.push(...result.part);
      progress.push({ fromBlock: current, toBlock: end, count: result.part.length, span, rpc: result.url, tries });
      current = end + 1;
      if (result.part.length < 50 && span < 500000) span = Math.min(500000, span * 2);
    } else {
      progress.push({ fromBlock: current, toBlock: end, span, error: 'all RPCs failed', tries });
      if (span <= 100) throw new Error(JSON.stringify(tries));
      span = Math.max(100, Math.floor(span / 2));
    }
  }
  return { logs, progress };
}

async function feedInfo(provider, address, blockTag) {
  if (!address || address === ethers.constants.AddressZero) return null;
  const code = await provider.getCode(address, blockTag);
  const c = new ethers.Contract(address, feedAbi, provider);
  const getters = {};
  for (const key of ['pool','twapPeriod','baseToken','quoteToken','asset','PRICE_FEED','MARKET','DURATION','aTokenToBTokenPriceFeed','bTokenToCTokenPriceFeed','dusdOracle','uspcOracle','xaueOracle','pharosOracle','ondoOracle','result','pairIndex']) {
    getters[key] = await safe(c[key]({ blockTag }));
  }
  return ser({
    address, codeBytes: Math.max((code.length - 2) / 2, 0), codeHash: ethers.utils.keccak256(code),
    latestRoundData: await safe(c.latestRoundData({ blockTag })), latestAnswer: await safe(c.latestAnswer({ blockTag })),
    latestTimestamp: await safe(c.latestTimestamp({ blockTag })), decimals: await safe(c.decimals({ blockTag })),
    description: await safe(c.description({ blockTag })), version: await safe(c.version({ blockTag })), getters
  });
}

async function oracleInfo(provider, address, asset, blockTag) {
  const v2 = new ethers.Contract(address, oracleV2Abi, provider);
  const configV2 = await safe(v2.oracles(asset, { blockTag }));
  if (configV2.ok) {
    const cfg = configV2.value;
    return ser({ shape: 'V2', address, asset, config: configV2, current: await safe(v2.getPrice(asset, { blockTag })),
      primary: await feedInfo(provider, cfg.aggregator, blockTag), backup: await feedInfo(provider, cfg.backupAggregator, blockTag) });
  }
  const v1 = new ethers.Contract(address, oracleV1Abi, provider);
  const configV1 = await safe(v1.oracles(asset, { blockTag }));
  return ser({ shape: configV1.ok ? 'V1' : 'unknown', address, asset, config: configV1,
    current: await safe(v1.getPrice(asset, { blockTag })),
    primary: configV1.ok ? await feedInfo(provider, configV1.value.aggregator, blockTag) : null,
    backup: configV1.ok ? await feedInfo(provider, configV1.value.backupAggregator, blockTag) : null });
}

async function orderInfo(provider, address, debtAddress, ftAddress, blockTag) {
  const order = new ethers.Contract(address, orderAbi, provider);
  const debt = new ethers.Contract(debtAddress, erc20Abi, provider);
  const ft = new ethers.Contract(ftAddress, erc20Abi, provider);
  const [reserves, expiry, paused, pool, virtualXtReserve, debtBalance, ftBalance] = await Promise.all([
    safe(order.tokenReserves({ blockTag })), safe(order.orderExpiryTimestamp({ blockTag })), safe(order.paused({ blockTag })),
    safe(order.pool({ blockTag })), safe(order.virtualXtReserve({ blockTag })),
    safe(debt.balanceOf(address, { blockTag })), safe(ft.balanceOf(address, { blockTag }))
  ]);
  let poolAssets = null;
  if (pool.ok && pool.value && pool.value !== ethers.constants.AddressZero) {
    const p = new ethers.Contract(pool.value, ['function balanceOf(address) view returns(uint256)','function convertToAssets(uint256) view returns(uint256)'], provider);
    const shares = await safe(p.balanceOf(address, { blockTag }));
    poolAssets = { shares };
    if (shares.ok) poolAssets.assets = await safe(p.convertToAssets(shares.value, { blockTag }));
  }
  return ser({ address, reserves, expiry, paused, pool, virtualXtReserve, debtBalance, ftBalance, poolAssets });
}

(async () => {
  fs.mkdirSync(OUT, { recursive: true });
  const { working, provider, chainId, blockNumber, block, attempts } = await providers();
  const marketMap = new Map(), factoryScans = [];
  for (const factory of FACTORIES) {
    const code = await provider.getCode(factory.address, blockNumber).catch(() => '0x');
    try {
      const scan = await logsAdaptive(working, factory.address, factory.fromBlock, blockNumber, [MARKET_TOPIC]);
      factoryScans.push({ ...factory, codeHash: ethers.utils.keccak256(code), codeBytes: Math.max((code.length - 2) / 2, 0), logCount: scan.logs.length, progress: scan.progress });
      for (const log of scan.logs) {
        if (log.topics.length < 4) continue;
        const market = topicAddress(log.topics[1]);
        marketMap.set(market.toLowerCase(), { market, factory: factory.address, createdBlock: log.blockNumber, createdTx: log.transactionHash, collateralEvent: topicAddress(log.topics[2]), debtEvent: topicAddress(log.topics[3]) });
      }
    } catch (e) { factoryScans.push({ ...factory, fatalError: String(e) }); }
  }
  const markets = [];
  for (const base of marketMap.values()) {
    try {
      const market = new ethers.Contract(base.market, marketAbi, provider);
      const code = await provider.getCode(base.market, blockNumber);
      const [name, isOpen, tokens, config] = await Promise.all([safe(market.name({ blockTag: blockNumber })), safe(market.isOpen({ blockTag: blockNumber })), safe(market.tokens({ blockTag: blockNumber })), safe(market.config({ blockTag: blockNumber }))]);
      if (!tokens.ok) { markets.push({ ...base, name, isOpen, tokens, config }); continue; }
      const t = tokens.value;
      const gt = new ethers.Contract(t.gt, gtAbi, provider), ft = new ethers.Contract(t.ft, erc20Abi, provider), xt = new ethers.Contract(t.xt, erc20Abi, provider), debt = new ethers.Contract(t.debtToken, erc20Abi, provider), collateral = new ethers.Contract(t.collateral, erc20Abi, provider);
      const [gtConfig, gtSupply, ftSupply, xtSupply, debtMarketBalance, collateralGtBalance, debtDecimals, debtSymbol, debtName, collateralDecimals, collateralSymbol, collateralName] = await Promise.all([
        safe(gt.getGtConfig({ blockTag: blockNumber })), safe(gt.totalSupply({ blockTag: blockNumber })), safe(ft.totalSupply({ blockTag: blockNumber })), safe(xt.totalSupply({ blockTag: blockNumber })), safe(debt.balanceOf(base.market, { blockTag: blockNumber })), safe(collateral.balanceOf(t.gt, { blockTag: blockNumber })), safe(debt.decimals({ blockTag: blockNumber })), safe(debt.symbol({ blockTag: blockNumber })), safe(debt.name({ blockTag: blockNumber })), safe(collateral.decimals({ blockTag: blockNumber })), safe(collateral.symbol({ blockTag: blockNumber })), safe(collateral.name({ blockTag: blockNumber }))
      ]);
      let debtOracle = null, collateralOracle = null;
      if (gtConfig.ok) {
        debtOracle = await oracleInfo(provider, gtConfig.value.loanConfig.oracle, t.debtToken, blockNumber);
        collateralOracle = await oracleInfo(provider, gtConfig.value.loanConfig.oracle, t.collateral, blockNumber);
      }
      let orderScan = { logs: [], progress: [] };
      try { orderScan = await logsAdaptive(working, base.market, base.createdBlock, blockNumber, [CREATE_ORDER_TOPIC]); } catch (_) {}
      const orderAddresses = [...new Set(orderScan.logs.filter(x => x.topics.length >= 3).map(x => topicAddress(x.topics[2]).toLowerCase()))];
      const orders = [];
      for (const lower of orderAddresses) orders.push(await orderInfo(provider, ethers.utils.getAddress(lower), t.debtToken, t.ft, blockNumber));
      const sum = (getter) => orders.reduce((a, x) => { const y = getter(x); return y?.ok ? a.add(y.value) : a; }, ethers.constants.Zero);
      const totalOrderDebt = sum(x => x.debtBalance), totalOrderFt = sum(x => x.ftBalance);
      const totalPoolAssets = orders.reduce((a, x) => x.poolAssets?.assets?.ok ? a.add(x.poolAssets.assets.value) : a, ethers.constants.Zero);
      const maturity = gtConfig.ok ? Number(gtConfig.value.maturity) : null;
      const minPrice = debtOracle?.shape === 'V2' && debtOracle.config.ok ? String(debtOracle.config.value.minPrice) : null;
      const currentPrice = debtOracle?.current?.ok ? String(debtOracle.current.value.price ?? debtOracle.current.value[0] ?? '') : null;
      const primaryAnswer = debtOracle?.primary?.latestRoundData?.ok ? String(debtOracle.primary.latestRoundData.value.answer) : null;
      markets.push(ser({ ...base, codeHash: ethers.utils.keccak256(code), codeBytes: Math.max((code.length - 2) / 2, 0), name, isOpen, tokens, config, debtMeta: { decimals: debtDecimals, symbol: debtSymbol, name: debtName }, collateralMeta: { decimals: collateralDecimals, symbol: collateralSymbol, name: collateralName }, balances: { gtSupply, ftSupply, xtSupply, debtMarketBalance, collateralGtBalance, totalOrderDebt, totalOrderFt, totalPoolAssets }, gtConfig, debtOracle, collateralOracle, orderScan: { logCount: orderScan.logs.length, progress: orderScan.progress }, orders, gates: { maturityFuture: maturity !== null ? maturity > block.timestamp : null, maturityTimestamp: maturity, isOpen: isOpen.ok ? Boolean(isOpen.value) : null, v2DebtOracle: debtOracle?.shape === 'V2', minPriceZero: minPrice === '0', currentDebtPriceZero: currentPrice === '0', primaryAnswerZero: primaryAnswer === '0', nonzeroFtSupply: ftSupply.ok ? !ethers.BigNumber.from(ftSupply.value).isZero() : null, nonzeroXtSupply: xtSupply.ok ? !ethers.BigNumber.from(xtSupply.value).isZero() : null, nonzeroGtSupply: gtSupply.ok ? !ethers.BigNumber.from(gtSupply.value).isZero() : null, nonzeroOrderLiquidity: !totalOrderDebt.isZero() || !totalOrderFt.isZero() || !totalPoolAssets.isZero(), orderCount: orders.length } }));
    } catch (e) { markets.push({ ...base, fatalError: String(e && e.stack ? e.stack : e) }); }
  }
  const candidates = markets.filter(m => m.gates?.maturityFuture && m.gates?.v2DebtOracle && m.gates?.minPriceZero && (m.gates?.nonzeroFtSupply || m.gates?.nonzeroGtSupply || m.gates?.nonzeroOrderLiquidity));
  const adapterHits = markets.filter(m => /xaue|pharos|uspc|dusd|ondo|twap|converter/i.test(JSON.stringify({ d: m.debtOracle, c: m.collateralOracle })));
  const result = { generatedAt: new Date().toISOString(), label: LABEL, scope: 'READ-ONLY; no transaction signed or broadcast', snapshot: { chainId, blockNumber, blockHash: block.hash, timestamp: block.timestamp }, rpcAttempts: attempts, factoryScans, marketCount: markets.length, candidateCount: candidates.length, candidates, adapterHitCount: adapterHits.length, adapterHits, markets };
  fs.writeFileSync(`${OUT}/FULL.json`, JSON.stringify(result, null, 2));
  fs.writeFileSync(`${OUT}/SUMMARY.json`, JSON.stringify({ generatedAt: result.generatedAt, label: LABEL, snapshot: result.snapshot, factoryScans: factoryScans.map(x => ({ address: x.address, logCount: x.logCount, fatalError: x.fatalError || null })), marketCount: markets.length, candidates: candidates.map(m => ({ market: m.market, name: m.name, debtMeta: m.debtMeta, collateralMeta: m.collateralMeta, gates: m.gates, balances: m.balances, debtOracle: m.debtOracle })), adapterHits: adapterHits.map(m => ({ market: m.market, name: m.name, debtMeta: m.debtMeta, collateralMeta: m.collateralMeta, gates: m.gates, balances: m.balances, debtOracle: m.debtOracle, collateralOracle: m.collateralOracle })) }, null, 2));
  fs.writeFileSync(`${OUT}/BLOCK.txt`, `${chainId}\n${blockNumber}\n${block.hash}\n${block.timestamp}\n`);
  console.log(fs.readFileSync(`${OUT}/SUMMARY.json`, 'utf8'));
})().catch(e => { fs.mkdirSync(OUT, { recursive: true }); const msg = String(e && e.stack ? e.stack : e); fs.writeFileSync(`${OUT}/ERROR.txt`, msg); console.error(msg); process.exit(1); });
