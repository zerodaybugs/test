'use strict';

const fs = require('fs');
const { ethers } = require('ethers');

const OUT = 'b2-market-output';
const CHAIN_ID = 223;
const FACTORY = ethers.utils.getAddress('0x5BA2d33fB50d08D7755787E729183FedD6a3F3e7');
const FROM_BLOCK = 31535305;
const MARKET_CREATED_TOPIC = '0x3f544a0e66146e1c515b04e3d00d07fabc299aa08db26f13ae0a2e3797503286';
const CREATE_ORDER_TOPIC = ethers.utils.id('CreateOrder(address,address)');
const RPCS = [
  'https://rpc.bsquared.network',
  'https://mainnet.b2-rpc.com',
  'https://b2-mainnet.alt.technology',
  'https://b2-mainnet-public.s.chainbase.com',
  'https://rpc.ankr.com/b2',
  'https://223.rpc.thirdweb.com',
];
const marketAbi = [
  'function name() view returns(string)',
  'function isOpen() view returns(bool)',
  'function tokens() view returns(address ft,address xt,address gt,address collateral,address debtToken)',
  'function config() view returns(tuple(address treasurer,uint64 maturity,tuple(uint32 lendTakerFeeRatio,uint32 lendMakerFeeRatio,uint32 borrowTakerFeeRatio,uint32 borrowMakerFeeRatio,uint32 mintGtFeeRatio,uint32 mintGtFeeRef) feeConfig))',
];
const gtAbi = [
  'function getGtConfig() view returns(tuple(address collateral,address debtToken,address ft,address treasurer,uint64 maturity,tuple(address oracle,uint32 liquidationLtv,uint32 maxLtv,bool liquidatable) loanConfig))',
  'function totalSupply() view returns(uint256)',
];
const oracleV2Abi = [
  'function getPrice(address) view returns(uint256 price,uint8 decimals)',
  'function oracles(address) view returns(address aggregator,address backupAggregator,int256 maxPrice,int256 minPrice,uint32 heartbeat,uint32 backupHeartbeat)',
];
const oracleV1Abi = [
  'function getPrice(address) view returns(uint256 price,uint8 decimals)',
  'function oracles(address) view returns(address aggregator,address backupAggregator,uint32 heartbeat)',
];
const feedAbi = [
  'function latestRoundData() view returns(uint80 roundId,int256 answer,uint256 startedAt,uint256 updatedAt,uint80 answeredInRound)',
  'function decimals() view returns(uint8)',
  'function description() view returns(string)',
  'function version() view returns(uint256)',
  'function pool() view returns(address)',
  'function twapPeriod() view returns(uint32)',
  'function baseToken() view returns(address)',
  'function quoteToken() view returns(address)',
  'function asset() view returns(address)',
  'function PRICE_FEED() view returns(address)',
  'function MARKET() view returns(address)',
  'function DURATION() view returns(uint32)',
  'function dusdOracle() view returns(address)',
  'function uspcOracle() view returns(address)',
  'function xaueOracle() view returns(address)',
  'function pharosOracle() view returns(address)',
  'function ondoOracle() view returns(address)',
];
const orderAbi = [
  'function tokenReserves() view returns(uint256 ftReserve,uint256 xtReserve)',
  'function orderExpiryTimestamp() view returns(uint64)',
  'function paused() view returns(bool)',
  'function pool() view returns(address)',
  'function virtualXtReserve() view returns(uint256)',
];
const erc20Abi = [
  'function balanceOf(address) view returns(uint256)',
  'function totalSupply() view returns(uint256)',
  'function decimals() view returns(uint8)',
  'function symbol() view returns(string)',
  'function name() view returns(string)',
];

function ser(value) {
  if (ethers.BigNumber.isBigNumber(value)) return value.toString();
  if (Array.isArray(value)) return value.map(ser);
  if (value && typeof value === 'object') {
    const out = {};
    for (const [key, item] of Object.entries(value)) if (!/^\d+$/.test(key)) out[key] = ser(item);
    return out;
  }
  return value;
}
async function safe(promise) {
  try { return { ok: true, value: ser(await promise) }; }
  catch (error) { return { ok: false, error: String(error && error.stack ? error.stack : error) }; }
}
async function discoverProviders() {
  const attempts = [];
  const working = [];
  for (const url of RPCS) {
    try {
      const provider = new ethers.providers.StaticJsonRpcProvider(url, { chainId: CHAIN_ID, name: 'b2' });
      const [network, blockNumber] = await Promise.all([provider.getNetwork(), provider.getBlockNumber()]);
      if (network.chainId !== CHAIN_ID) throw new Error(`wrong chain ${network.chainId}`);
      working.push({ url, provider, blockNumber });
      attempts.push({ url, ok: true, chainId: network.chainId, blockNumber });
    } catch (error) { attempts.push({ url, ok: false, error: String(error) }); }
  }
  if (!working.length) throw new Error(`no working RPC: ${JSON.stringify(attempts)}`);
  const blockNumber = Math.min(...working.map((x) => x.blockNumber));
  const provider = working[0].provider;
  const block = await provider.getBlock(blockNumber);
  return { working, provider, attempts, blockNumber, block };
}
async function rangeLogs(working, address, fromBlock, toBlock, topics) {
  let current = fromBlock;
  let span = 100000;
  const minSpan = 100;
  const logs = [];
  const progress = [];
  while (current <= toBlock) {
    const end = Math.min(toBlock, current + span - 1);
    let result = null;
    const attempts = [];
    for (const endpoint of working) {
      try {
        const part = await endpoint.provider.getLogs({ address, fromBlock: current, toBlock: end, topics });
        result = { logs: part, rpc: endpoint.url };
        attempts.push({ url: endpoint.url, ok: true, count: part.length });
        break;
      } catch (error) { attempts.push({ url: endpoint.url, ok: false, error: String(error) }); }
    }
    if (result) {
      logs.push(...result.logs);
      progress.push({ fromBlock: current, toBlock: end, span, count: result.logs.length, rpc: result.rpc, attempts });
      current = end + 1;
      if (result.logs.length < 100 && span < 500000) span = Math.min(500000, span * 2);
    } else {
      progress.push({ fromBlock: current, toBlock: end, span, error: 'all RPCs failed', attempts });
      if (span <= minSpan) throw new Error(JSON.stringify(attempts));
      span = Math.max(minSpan, Math.floor(span / 2));
    }
  }
  return { logs, progress };
}
function topicAddress(topic) {
  return ethers.utils.getAddress(`0x${topic.slice(-40)}`);
}
async function feedInfo(provider, address, blockTag) {
  if (!address || address === ethers.constants.AddressZero) return null;
  const code = await provider.getCode(address, blockTag);
  const feed = new ethers.Contract(address, feedAbi, provider);
  const getters = {};
  for (const key of ['pool','twapPeriod','baseToken','quoteToken','asset','PRICE_FEED','MARKET','DURATION','dusdOracle','uspcOracle','xaueOracle','pharosOracle','ondoOracle']) {
    getters[key] = await safe(feed[key]({ blockTag }));
  }
  return ser({
    address,
    codeBytes: Math.max((code.length - 2) / 2, 0),
    codeHash: ethers.utils.keccak256(code),
    latestRoundData: await safe(feed.latestRoundData({ blockTag })),
    decimals: await safe(feed.decimals({ blockTag })),
    description: await safe(feed.description({ blockTag })),
    version: await safe(feed.version({ blockTag })),
    getters,
  });
}
async function oracleInfo(provider, address, asset, blockTag) {
  const v2 = new ethers.Contract(address, oracleV2Abi, provider);
  const configV2 = await safe(v2.oracles(asset, { blockTag }));
  if (configV2.ok) {
    const config = configV2.value;
    return ser({
      shape: 'V2', address, asset, config: configV2,
      current: await safe(v2.getPrice(asset, { blockTag })),
      primary: await feedInfo(provider, config.aggregator, blockTag),
      backup: await feedInfo(provider, config.backupAggregator, blockTag),
    });
  }
  const v1 = new ethers.Contract(address, oracleV1Abi, provider);
  const configV1 = await safe(v1.oracles(asset, { blockTag }));
  return ser({
    shape: configV1.ok ? 'V1' : 'unknown', address, asset, config: configV1,
    current: await safe(v1.getPrice(asset, { blockTag })),
    primary: configV1.ok ? await feedInfo(provider, configV1.value.aggregator, blockTag) : null,
    backup: configV1.ok ? await feedInfo(provider, configV1.value.backupAggregator, blockTag) : null,
  });
}
async function inspectOrder(provider, address, debtToken, ft, blockTag) {
  const order = new ethers.Contract(address, orderAbi, provider);
  const debt = new ethers.Contract(debtToken, erc20Abi, provider);
  const ftToken = new ethers.Contract(ft, erc20Abi, provider);
  const [reserves, expiry, paused, pool, virtualXtReserve, debtBalance, ftBalance] = await Promise.all([
    safe(order.tokenReserves({ blockTag })),
    safe(order.orderExpiryTimestamp({ blockTag })),
    safe(order.paused({ blockTag })),
    safe(order.pool({ blockTag })),
    safe(order.virtualXtReserve({ blockTag })),
    safe(debt.balanceOf(address, { blockTag })),
    safe(ftToken.balanceOf(address, { blockTag })),
  ]);
  let poolAssets = null;
  if (pool.ok && pool.value !== ethers.constants.AddressZero) {
    const poolToken = new ethers.Contract(pool.value, [
      'function balanceOf(address) view returns(uint256)',
      'function convertToAssets(uint256) view returns(uint256)',
    ], provider);
    const shares = await safe(poolToken.balanceOf(address, { blockTag }));
    poolAssets = { shares };
    if (shares.ok) poolAssets.assets = await safe(poolToken.convertToAssets(shares.value, { blockTag }));
  }
  return { address, reserves, expiry, paused, pool, virtualXtReserve, debtBalance, ftBalance, poolAssets };
}
async function inspectMarket(provider, base, blockTag) {
  const market = new ethers.Contract(base.market, marketAbi, provider);
  const code = await provider.getCode(base.market, blockTag);
  const [name, isOpen, tokens, config] = await Promise.all([
    safe(market.name({ blockTag })),
    safe(market.isOpen({ blockTag })),
    safe(market.tokens({ blockTag })),
    safe(market.config({ blockTag })),
  ]);
  if (!tokens.ok) return { ...base, codeHash: ethers.utils.keccak256(code), name, isOpen, tokens, config };
  const t = tokens.value;
  const gt = new ethers.Contract(t.gt, gtAbi, provider);
  const ft = new ethers.Contract(t.ft, erc20Abi, provider);
  const xt = new ethers.Contract(t.xt, erc20Abi, provider);
  const debt = new ethers.Contract(t.debtToken, erc20Abi, provider);
  const collateral = new ethers.Contract(t.collateral, erc20Abi, provider);
  const [gtConfig, gtSupply, ftSupply, xtSupply, debtMarketBalance, collateralGtBalance, debtDecimals, debtSymbol, collateralDecimals, collateralSymbol] = await Promise.all([
    safe(gt.getGtConfig({ blockTag })), safe(gt.totalSupply({ blockTag })),
    safe(ft.totalSupply({ blockTag })), safe(xt.totalSupply({ blockTag })),
    safe(debt.balanceOf(base.market, { blockTag })), safe(collateral.balanceOf(t.gt, { blockTag })),
    safe(debt.decimals({ blockTag })), safe(debt.symbol({ blockTag })),
    safe(collateral.decimals({ blockTag })), safe(collateral.symbol({ blockTag })),
  ]);
  let debtOracle = null;
  if (gtConfig.ok) debtOracle = await oracleInfo(provider, gtConfig.value.loanConfig.oracle, t.debtToken, blockTag);
  const orderScan = await rangeLogs([{ url: 'state', provider }], base.market, base.createdBlock, blockTag, [CREATE_ORDER_TOPIC]);
  const orderMap = new Map();
  for (const log of orderScan.logs) {
    if (log.topics.length < 3) continue;
    orderMap.set(topicAddress(log.topics[2]).toLowerCase(), topicAddress(log.topics[2]));
  }
  const orders = [];
  for (const orderAddress of orderMap.values()) orders.push(await inspectOrder(provider, orderAddress, t.debtToken, t.ft, blockTag));
  const minPrice = debtOracle?.shape === 'V2' && debtOracle.config.ok ? String(debtOracle.config.value.minPrice) : null;
  const maturity = gtConfig.ok ? Number(gtConfig.value.maturity) : null;
  const totalOrderDebt = orders.reduce((sum, order) => {
    if (!order.debtBalance.ok) return sum;
    return sum.add(order.debtBalance.value);
  }, ethers.constants.Zero);
  const totalPoolAssets = orders.reduce((sum, order) => {
    if (!order.poolAssets?.assets?.ok) return sum;
    return sum.add(order.poolAssets.assets.value);
  }, ethers.constants.Zero);
  return ser({
    ...base,
    codeBytes: Math.max((code.length - 2) / 2, 0), codeHash: ethers.utils.keccak256(code),
    name, isOpen, tokens, config,
    metadata: { debtDecimals, debtSymbol, collateralDecimals, collateralSymbol },
    balances: { gtSupply, ftSupply, xtSupply, debtMarketBalance, collateralGtBalance, totalOrderDebt, totalPoolAssets },
    gtConfig, debtOracle,
    orderScan: { logCount: orderScan.logs.length, progress: orderScan.progress },
    orders,
    gates: {
      maturityFuture: maturity != null ? maturity > blockTag : null,
      maturityTimestamp: maturity,
      v2Oracle: debtOracle?.shape === 'V2',
      minPriceZero: minPrice === '0',
      nonzeroFtSupply: ftSupply.ok ? !ethers.BigNumber.from(ftSupply.value).isZero() : null,
      nonzeroGtSupply: gtSupply.ok ? !ethers.BigNumber.from(gtSupply.value).isZero() : null,
      nonzeroOrderLiquidity: !totalOrderDebt.isZero() || !totalPoolAssets.isZero(),
      orderCount: orders.length,
    },
  });
}

(async () => {
  fs.mkdirSync(OUT, { recursive: true });
  const { working, provider, attempts, blockNumber, block } = await discoverProviders();
  const factoryCode = await provider.getCode(FACTORY, blockNumber);
  const scan = await rangeLogs(working, FACTORY, FROM_BLOCK, blockNumber, [MARKET_CREATED_TOPIC]);
  const map = new Map();
  for (const log of scan.logs) {
    if (log.topics.length < 4) continue;
    const market = topicAddress(log.topics[1]);
    map.set(market.toLowerCase(), {
      market,
      collateralEvent: topicAddress(log.topics[2]),
      debtEvent: topicAddress(log.topics[3]),
      createdBlock: log.blockNumber,
      createdTx: log.transactionHash,
    });
  }
  const markets = [];
  for (const base of map.values()) markets.push(await inspectMarket(provider, base, blockNumber));
  const candidates = markets.filter((m) =>
    m.gates?.maturityFuture && m.gates?.v2Oracle && m.gates?.minPriceZero &&
    (m.gates?.nonzeroFtSupply || m.gates?.nonzeroGtSupply || m.gates?.nonzeroOrderLiquidity)
  );
  const result = {
    generatedAt: new Date().toISOString(), scope: 'READ-ONLY. No transaction signed or broadcast.',
    chain: { chainId: CHAIN_ID, blockNumber, blockHash: block.hash, timestamp: block.timestamp, rpcAttempts: attempts },
    factory: { address: FACTORY, fromBlock: FROM_BLOCK, codeBytes: (factoryCode.length - 2) / 2, codeHash: ethers.utils.keccak256(factoryCode), logCount: scan.logs.length, progress: scan.progress },
    marketCount: markets.length, candidateCount: candidates.length, candidates, markets,
  };
  fs.writeFileSync(`${OUT}/market-inventory.json`, JSON.stringify(result, null, 2));
  fs.writeFileSync(`${OUT}/block.txt`, `${blockNumber}\n${block.hash}\n${block.timestamp}\n`);
  fs.writeFileSync(`${OUT}/summary.json`, JSON.stringify({ chain: result.chain, factory: { address: FACTORY, logCount: scan.logs.length }, marketCount: markets.length, candidateCount: candidates.length, candidates: candidates.map((m) => ({ market: m.market, name: m.name, gates: m.gates, metadata: m.metadata, balances: m.balances })) }, null, 2));
  console.log(fs.readFileSync(`${OUT}/summary.json`, 'utf8'));
})().catch((error) => {
  fs.mkdirSync(OUT, { recursive: true });
  const message = String(error && error.stack ? error.stack : error);
  fs.writeFileSync(`${OUT}/error.txt`, message);
  console.error(message);
  process.exit(1);
});
