'use strict';

const fs = require('fs');
const { ethers } = require('ethers');
const sdk = require('@defillama/sdk');

const RPCS = [
  'https://ethereum-rpc.publicnode.com',
  'https://eth.llamarpc.com',
  'https://eth.drpc.org',
  'https://1rpc.io/eth'
];
const FACTORIES = [
  ['0xF2BDa87CA467eB90A1b68f824cB136baA68a8177', 23430000],
  ['0x5b8B26a6734B5eABDBe6C5A19580Ab2D0424f027', 23430000],
  ['0xc1E9640F04B802Bbf0B02a4e9Fe394039AbE8B59', 24883366]
].map(([address, fromBlock]) => ({ address: ethers.utils.getAddress(address), fromBlock }));

const OUT = 'evidence';
const MARKET_TOPIC = '0x3f544a0e66146e1c515b04e3d00d07fabc299aa08db26f13ae0a2e3797503286';
const CREATE_ORDER_TOPIC = ethers.utils.id('CreateOrder(address,address)');

const marketAbi = [
  'function name() view returns(string)',
  'function tokens() view returns(address ft,address xt,address gt,address collateral,address debtToken)',
  'function config() view returns(tuple(address treasurer,uint64 maturity,tuple(uint32 lendTakerFeeRatio,uint32 lendMakerFeeRatio,uint32 borrowTakerFeeRatio,uint32 borrowMakerFeeRatio,uint32 mintGtFeeRatio,uint32 mintGtFeeRef) feeConfig))',
  'function isOpen() view returns(bool)'
];
const gtAbi = [
  'function getGtConfig() view returns(tuple(address collateral,address debtToken,address ft,address treasurer,uint64 maturity,tuple(address oracle,uint32 liquidationLtv,uint32 maxLtv,bool liquidatable) loanConfig))',
  'function totalSupply() view returns(uint256)'
];
const orderAbi = [
  'function maker() view returns(address)',
  'function tokenReserves() view returns(uint256 ftReserve,uint256 xtReserve)',
  'function orderExpiryTimestamp() view returns(uint256)',
  'function virtualXtReserve() view returns(uint256)',
  'function maxXtReserve() view returns(uint256)'
];
const erc20Abi = [
  'function symbol() view returns(string)',
  'function decimals() view returns(uint8)',
  'function totalSupply() view returns(uint256)',
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
  'function decimals() view returns(uint8)',
  'function description() view returns(string)',
  'function version() view returns(uint256)',
  'function asset() view returns(address)',
  'function adapter() view returns(address)',
  'function PRICE_FEED() view returns(address)',
  'function MARKET() view returns(address)',
  'function DURATION() view returns(uint32)',
  'function dusdOracle() view returns(address)',
  'function uspcOracle() view returns(address)',
  'function xaueOracle() view returns(address)',
  'function ondoOracle() view returns(address)',
  'function pharosOracle() view returns(address)',
  'function pool() view returns(address)',
  'function twapPeriod() view returns(uint32)',
  'function baseToken() view returns(address)',
  'function quoteToken() view returns(address)',
  'function beefyVault() view returns(address)',
  'function lpToken() view returns(address)',
  'function token0PriceFeed() view returns(address)',
  'function token1PriceFeed() view returns(address)',
  'function maxUpdateInterval() view returns(uint256)'
];

function serialise(value) {
  if (ethers.BigNumber.isBigNumber(value)) return value.toString();
  if (Array.isArray(value)) return value.map(serialise);
  if (value && typeof value === 'object') {
    const out = {};
    for (const [key, item] of Object.entries(value)) {
      if (!/^\d+$/.test(key)) out[key] = serialise(item);
    }
    return out;
  }
  return value;
}

async function safe(promise) {
  try { return { ok: true, value: serialise(await promise) }; }
  catch (error) { return { ok: false, error: String(error) }; }
}

async function chooseProvider() {
  const attempts = [];
  for (const url of RPCS) {
    try {
      const provider = new ethers.providers.JsonRpcProvider(url);
      const [network, blockNumber] = await Promise.all([provider.getNetwork(), provider.getBlockNumber()]);
      if (network.chainId !== 1) throw new Error(`unexpected chainId ${network.chainId}`);
      attempts.push({ url, ok: true, blockNumber });
      return { provider, url, blockNumber, attempts };
    } catch (error) {
      attempts.push({ url, ok: false, error: String(error) });
    }
  }
  throw new Error(`No working Ethereum RPC: ${JSON.stringify(attempts)}`);
}

function normalizeLog(log) {
  return {
    address: log.address || log.source,
    topics: log.topics || [log.topic0, log.topic1, log.topic2, log.topic3].filter(Boolean),
    data: log.data,
    blockNumber: Number(log.blockNumber ?? log.block_number ?? 0),
    transactionHash: log.transactionHash || log.transaction_hash || '',
    logIndex: Number(log.logIndex ?? log.index ?? log.log_index ?? 0)
  };
}

async function directLogs(provider, address, fromBlock, toBlock, topic) {
  let current = fromBlock;
  let span = 100000;
  const logs = [];
  while (current <= toBlock) {
    const end = Math.min(toBlock, current + span - 1);
    try {
      const part = await provider.getLogs({ address, fromBlock: current, toBlock: end, topics: [topic] });
      logs.push(...part.map(normalizeLog));
      current = end + 1;
      if (part.length < 100 && span < 500000) span = Math.min(500000, span * 2);
    } catch (error) {
      if (span <= 100) throw error;
      span = Math.max(100, Math.floor(span / 2));
    }
  }
  return logs;
}

async function indexedLogs(address, fromBlock, toBlock, topic) {
  const logs = await sdk.getEventLogs({
    chain: 'ethereum',
    target: address,
    topic,
    fromBlock,
    toBlock,
    entireLog: true,
    parseLog: false,
    skipCache: true,
    maxBlockRange: 500000
  });
  return (logs || []).map(normalizeLog);
}

async function logsWithFallback(provider, address, fromBlock, toBlock, topic) {
  const attempts = [];
  try {
    const logs = await directLogs(provider, address, fromBlock, toBlock, topic);
    attempts.push({ source: 'rpc', ok: true, count: logs.length });
    return { logs, attempts, source: 'rpc' };
  } catch (error) {
    attempts.push({ source: 'rpc', ok: false, error: String(error) });
  }
  try {
    const logs = await indexedLogs(address, fromBlock, toBlock, topic);
    attempts.push({ source: 'defillama', ok: true, count: logs.length });
    return { logs, attempts, source: 'defillama' };
  } catch (error) {
    attempts.push({ source: 'defillama', ok: false, error: String(error) });
    return { logs: [], attempts, source: null, fatalError: 'all log sources failed' };
  }
}

async function inspectFeed(provider, address, blockTag) {
  if (!address || address === ethers.constants.AddressZero) return null;
  const feed = new ethers.Contract(address, feedAbi, provider);
  const code = await provider.getCode(address, blockTag);
  const getters = {};
  for (const key of [
    'asset', 'adapter', 'PRICE_FEED', 'MARKET', 'DURATION', 'dusdOracle', 'uspcOracle',
    'xaueOracle', 'ondoOracle', 'pharosOracle', 'pool', 'twapPeriod', 'baseToken',
    'quoteToken', 'beefyVault', 'lpToken', 'token0PriceFeed', 'token1PriceFeed', 'maxUpdateInterval'
  ]) getters[key] = await safe(feed[key]({ blockTag }));
  return serialise({
    address,
    codeBytes: Math.max((code.length - 2) / 2, 0),
    codeHash: ethers.utils.keccak256(code),
    latestRoundData: await safe(feed.latestRoundData({ blockTag })),
    decimals: await safe(feed.decimals({ blockTag })),
    description: await safe(feed.description({ blockTag })),
    version: await safe(feed.version({ blockTag })),
    getters
  });
}

async function inspectOracle(provider, oracleAddress, asset, blockTag) {
  const v2 = new ethers.Contract(oracleAddress, oracleV2Abi, provider);
  const v2Config = await safe(v2.oracles(asset, { blockTag }));
  if (v2Config.ok) {
    const config = v2Config.value;
    return serialise({
      shape: 'V2', address: oracleAddress, asset, config: v2Config,
      current: await safe(v2.getPrice(asset, { blockTag })),
      primary: await inspectFeed(provider, config.aggregator, blockTag),
      backup: await inspectFeed(provider, config.backupAggregator, blockTag)
    });
  }
  const v1 = new ethers.Contract(oracleAddress, oracleV1Abi, provider);
  const v1Config = await safe(v1.oracles(asset, { blockTag }));
  return serialise({
    shape: v1Config.ok ? 'V1' : 'unknown', address: oracleAddress, asset, config: v1Config,
    current: await safe(v1.getPrice(asset, { blockTag })),
    primary: v1Config.ok ? await inspectFeed(provider, v1Config.value.aggregator, blockTag) : null,
    backup: v1Config.ok ? await inspectFeed(provider, v1Config.value.backupAggregator, blockTag) : null
  });
}

async function inspectOrder(provider, address, tokens, blockTag) {
  const order = new ethers.Contract(address, orderAbi, provider);
  const ft = new ethers.Contract(tokens.ft, erc20Abi, provider);
  const xt = new ethers.Contract(tokens.xt, erc20Abi, provider);
  const [maker, reserves, expiry, virtualXtReserve, maxXtReserve, ftBalance, xtBalance, code] = await Promise.all([
    order.maker({ blockTag }).catch(() => ethers.constants.AddressZero),
    order.tokenReserves({ blockTag }),
    order.orderExpiryTimestamp({ blockTag }).catch(() => ethers.constants.Zero),
    order.virtualXtReserve({ blockTag }).catch(() => ethers.constants.Zero),
    order.maxXtReserve({ blockTag }).catch(() => ethers.constants.Zero),
    ft.balanceOf(address, { blockTag }),
    xt.balanceOf(address, { blockTag }),
    provider.getCode(address, blockTag)
  ]);
  return serialise({ address, maker, reserves, expiry, virtualXtReserve, maxXtReserve, ftBalance, xtBalance, codeHash: ethers.utils.keccak256(code) });
}

async function inspectMarket(provider, base, blockTag) {
  const market = new ethers.Contract(base.market, marketAbi, provider);
  const [name, tokens, config, isOpen, code] = await Promise.all([
    market.name({ blockTag }).catch(() => ''),
    market.tokens({ blockTag }),
    market.config({ blockTag }),
    market.isOpen({ blockTag }).catch(() => null),
    provider.getCode(base.market, blockTag)
  ]);
  const ft = new ethers.Contract(tokens.ft, erc20Abi, provider);
  const xt = new ethers.Contract(tokens.xt, erc20Abi, provider);
  const gt = new ethers.Contract(tokens.gt, gtAbi, provider);
  const collateral = new ethers.Contract(tokens.collateral, erc20Abi, provider);
  const debt = new ethers.Contract(tokens.debtToken, erc20Abi, provider);
  const [
    gtConfig, gtSupply, ftSupply, xtSupply, ftMarketBalance, xtMarketBalance,
    debtMarketBalance, collateralGtBalance, debtSymbol, debtDecimals,
    collateralSymbol, collateralDecimals
  ] = await Promise.all([
    gt.getGtConfig({ blockTag }), gt.totalSupply({ blockTag }), ft.totalSupply({ blockTag }), xt.totalSupply({ blockTag }),
    ft.balanceOf(base.market, { blockTag }), xt.balanceOf(base.market, { blockTag }), debt.balanceOf(base.market, { blockTag }),
    collateral.balanceOf(tokens.gt, { blockTag }), debt.symbol({ blockTag }).catch(() => ''), debt.decimals({ blockTag }),
    collateral.symbol({ blockTag }).catch(() => ''), collateral.decimals({ blockTag })
  ]);

  const orderScan = await logsWithFallback(provider, base.market, base.createdBlock || 0, blockTag, CREATE_ORDER_TOPIC);
  const orderAddresses = [];
  for (const log of orderScan.logs) {
    if (log.topics && log.topics.length >= 3) orderAddresses.push(ethers.utils.getAddress(`0x${log.topics[2].slice(-40)}`));
  }
  const orders = [];
  for (const lower of [...new Set(orderAddresses.map((x) => x.toLowerCase()))]) {
    try { orders.push(await inspectOrder(provider, ethers.utils.getAddress(lower), tokens, blockTag)); }
    catch (error) { orders.push({ address: lower, fatalError: String(error) }); }
  }

  return serialise({
    ...base, name, isOpen, codeHash: ethers.utils.keccak256(code), config, tokens,
    debtMeta: { symbol: debtSymbol, decimals: debtDecimals },
    collateralMeta: { symbol: collateralSymbol, decimals: collateralDecimals },
    balances: { gtSupply, ftSupply, xtSupply, ftMarketBalance, xtMarketBalance, debtMarketBalance, collateralGtBalance },
    gtConfig,
    debtOracle: await inspectOracle(provider, gtConfig.loanConfig.oracle, tokens.debtToken, blockTag),
    collateralOracle: await inspectOracle(provider, gtConfig.loanConfig.oracle, tokens.collateral, blockTag),
    orderScan: { source: orderScan.source, attempts: orderScan.attempts, count: orders.length },
    orders
  });
}

(async () => {
  fs.mkdirSync(OUT, { recursive: true });
  const { provider, url, blockNumber, attempts } = await chooseProvider();
  const block = await provider.getBlock(blockNumber);
  const marketMap = new Map();
  const factoryScans = [];

  for (const factory of FACTORIES) {
    const scan = await logsWithFallback(provider, factory.address, factory.fromBlock, blockNumber, MARKET_TOPIC);
    factoryScans.push({ ...factory, source: scan.source, attempts: scan.attempts, count: scan.logs.length, fatalError: scan.fatalError || null });
    for (const log of scan.logs) {
      if (!log.topics || log.topics.length < 4) continue;
      const market = ethers.utils.getAddress(`0x${log.topics[1].slice(-40)}`);
      marketMap.set(market.toLowerCase(), {
        market, factory: factory.address, createdBlock: Number(log.blockNumber), createdTx: log.transactionHash,
        collateralEvent: ethers.utils.getAddress(`0x${log.topics[2].slice(-40)}`),
        debtEvent: ethers.utils.getAddress(`0x${log.topics[3].slice(-40)}`)
      });
    }
  }

  const markets = [];
  for (const base of marketMap.values()) {
    try { markets.push(await inspectMarket(provider, base, blockNumber)); }
    catch (error) { markets.push({ ...base, fatalError: String(error) }); }
    fs.writeFileSync(`${OUT}/PARTIAL.json`, JSON.stringify({ blockNumber, marketCount: markets.length, markets }, null, 2));
  }

  const output = {
    rpc: url, rpcAttempts: attempts,
    snapshot: { blockNumber, blockHash: block.hash, timestamp: block.timestamp },
    factoryScans, marketCount: markets.length, markets
  };
  fs.writeFileSync(`${OUT}/INVENTORY.json`, JSON.stringify(output, null, 2));
  fs.writeFileSync(`${OUT}/SUMMARY.json`, JSON.stringify({
    snapshot: output.snapshot,
    marketCount: markets.length,
    liveMarkets: markets.filter((m) => Number(m.gtConfig?.maturity || 0) > block.timestamp && (m.balances?.ftSupply !== '0' || m.balances?.gtSupply !== '0')).map((m) => ({
      market: m.market, name: m.name, debt: m.debtMeta?.symbol, collateral: m.collateralMeta?.symbol,
      maturity: m.gtConfig?.maturity, balances: m.balances,
      debtFeed: m.debtOracle?.primary?.address, collateralFeed: m.collateralOracle?.primary?.address,
      collateralAdapter: m.collateralOracle?.primary?.getters?.adapter,
      orderCount: m.orders?.length || 0
    }))
  }, null, 2));
  console.log(JSON.stringify({ status: 'complete', blockNumber, marketCount: markets.length }));
})().catch((error) => {
  fs.mkdirSync(OUT, { recursive: true });
  fs.writeFileSync(`${OUT}/ERROR.txt`, String(error.stack || error));
  console.error('inventory failed');
  process.exit(1);
});
