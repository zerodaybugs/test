const fs = require('fs');
const { ethers } = require('ethers');

const LABEL = process.env.LABEL;
const RPCS = process.env.RPCS.split(',').map((x) => x.trim()).filter(Boolean);
const FACTORIES = process.env.FACTORIES.split(',').map((x) => {
  const [address, from] = x.split(':');
  return { address: ethers.utils.getAddress(address), fromBlock: Number(from) };
});
const OUT = 'encrypted-all-markets';
const MARKET_TOPIC = '0x3f544a0e66146e1c515b04e3d00d07fabc299aa08db26f13ae0a2e3797503286';

const marketAbi = [
  'function name() view returns(string)',
  'function tokens() view returns(address ft,address xt,address gt,address collateral,address debtToken)',
  'function config() view returns(tuple(address treasurer,uint64 maturity,tuple(uint32 lendTakerFeeRatio,uint32 lendMakerFeeRatio,uint32 borrowTakerFeeRatio,uint32 borrowMakerFeeRatio,uint32 mintGtFeeRatio,uint32 mintGtFeeRef) feeConfig))',
];
const gtAbi = [
  'function getGtConfig() view returns(tuple(address collateral,address debtToken,address ft,address treasurer,uint64 maturity,tuple(address oracle,uint32 liquidationLtv,uint32 maxLtv,bool liquidatable) loanConfig))',
  'function totalSupply() view returns(uint256)',
];
const erc20Abi = [
  'function symbol() view returns(string)',
  'function decimals() view returns(uint8)',
  'function totalSupply() view returns(uint256)',
  'function balanceOf(address) view returns(uint256)',
];
const oracleV2Abi = [
  'function getPrice(address) view returns(uint256,uint8)',
  'function oracles(address) view returns(address aggregator,address backupAggregator,int256 maxPrice,int256 minPrice,uint32 heartbeat,uint32 backupHeartbeat)',
];
const oracleV1Abi = [
  'function getPrice(address) view returns(uint256,uint8)',
  'function oracles(address) view returns(address aggregator,address backupAggregator,uint32 heartbeat)',
];
const feedAbi = [
  'function latestRoundData() view returns(uint80,int256,uint256,uint256,uint80)',
  'function decimals() view returns(uint8)',
  'function description() view returns(string)',
  'function version() view returns(uint256)',
  'function pool() view returns(address)',
  'function twapPeriod() view returns(uint32)',
  'function baseToken() view returns(address)',
  'function quoteToken() view returns(address)',
  'function asset() view returns(address)',
  'function aTokenToBTokenPriceFeed() view returns(address)',
  'function bTokenToCTokenPriceFeed() view returns(address)',
  'function PRICE_FEED() view returns(address)',
  'function MARKET() view returns(address)',
  'function DURATION() view returns(uint32)',
  'function dusdOracle() view returns(address)',
  'function xaueOracle() view returns(address)',
  'function pharosOracle() view returns(address)',
  'function result() view returns(uint256)',
  'function pairIndex() view returns(uint256)',
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
  try {
    return { ok: true, value: serialise(await promise) };
  } catch (error) {
    return { ok: false, error: String(error) };
  }
}

async function discoverProviders() {
  const attempts = [];
  const providers = [];
  for (const url of RPCS) {
    try {
      const provider = new ethers.providers.JsonRpcProvider(url);
      const [network, blockNumber] = await Promise.all([provider.getNetwork(), provider.getBlockNumber()]);
      attempts.push({ url, ok: true, chainId: network.chainId, blockNumber });
      providers.push({ provider, url, chainId: network.chainId, blockNumber });
    } catch (error) {
      attempts.push({ url, ok: false, error: String(error) });
    }
  }
  if (providers.length === 0) throw new Error(`No working RPC: ${JSON.stringify(attempts)}`);
  const expected = providers[0].chainId;
  const sameChain = providers.filter((x) => x.chainId === expected);
  return { providers: sameChain, attempts };
}

async function getLogsAdaptive(provider, address, fromBlock, toBlock) {
  const logs = [];
  const progress = [];
  let current = fromBlock;
  let span = 100000;
  while (current <= toBlock) {
    const end = Math.min(toBlock, current + span - 1);
    try {
      const part = await provider.getLogs({
        address,
        fromBlock: current,
        toBlock: end,
        topics: [MARKET_TOPIC],
      });
      logs.push(...part);
      progress.push({ from: current, to: end, count: part.length, span });
      current = end + 1;
      if (part.length < 100 && span < 500000) span = Math.min(500000, span * 2);
    } catch (error) {
      progress.push({ from: current, to: end, span, error: String(error) });
      if (span <= 100) throw error;
      span = Math.max(100, Math.floor(span / 2));
    }
  }
  return { logs, progress };
}

async function scanFactory(providers, factory, latestBlock) {
  const attempts = [];
  for (const endpoint of providers) {
    try {
      const result = await getLogsAdaptive(endpoint.provider, factory.address, factory.fromBlock, latestBlock);
      attempts.push({ rpc: endpoint.url, ok: true, logCount: result.logs.length });
      return { ...result, rpc: endpoint.url, attempts };
    } catch (error) {
      attempts.push({ rpc: endpoint.url, ok: false, error: String(error) });
    }
  }
  return { logs: [], progress: [], rpc: null, attempts, fatalError: 'all RPC endpoints failed historical log scan' };
}

async function feedInfo(provider, address, blockTag) {
  if (!address || address === ethers.constants.AddressZero) return null;
  const feed = new ethers.Contract(address, feedAbi, provider);
  const code = await provider.getCode(address, blockTag);
  const getters = {};
  for (const key of [
    'pool', 'twapPeriod', 'baseToken', 'quoteToken', 'asset',
    'aTokenToBTokenPriceFeed', 'bTokenToCTokenPriceFeed',
    'PRICE_FEED', 'MARKET', 'DURATION', 'dusdOracle', 'xaueOracle',
    'pharosOracle', 'result', 'pairIndex',
  ]) {
    getters[key] = await safe(feed[key]({ blockTag }));
  }
  return serialise({
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

async function oracleInfo(provider, oracleAddress, asset, blockTag) {
  const v2 = new ethers.Contract(oracleAddress, oracleV2Abi, provider);
  const configV2 = await safe(v2.oracles(asset, { blockTag }));
  if (configV2.ok) {
    const config = configV2.value;
    return {
      version: 'V2-shape',
      address: oracleAddress,
      asset,
      config: configV2,
      current: await safe(v2.getPrice(asset, { blockTag })),
      primary: await feedInfo(provider, config.aggregator, blockTag),
      backup: await feedInfo(provider, config.backupAggregator, blockTag),
    };
  }
  const v1 = new ethers.Contract(oracleAddress, oracleV1Abi, provider);
  const configV1 = await safe(v1.oracles(asset, { blockTag }));
  return {
    version: configV1.ok ? 'V1-shape' : 'unknown',
    address: oracleAddress,
    asset,
    config: configV1,
    current: await safe(v1.getPrice(asset, { blockTag })),
    primary: configV1.ok ? await feedInfo(provider, configV1.value.aggregator, blockTag) : null,
    backup: configV1.ok ? await feedInfo(provider, configV1.value.backupAggregator, blockTag) : null,
  };
}

async function inspectMarket(provider, base, blockTag) {
  const market = new ethers.Contract(base.market, marketAbi, provider);
  const [name, tokens, config, code] = await Promise.all([
    market.name({ blockTag }).catch(() => ''),
    market.tokens({ blockTag }),
    market.config({ blockTag }),
    provider.getCode(base.market, blockTag),
  ]);
  const ft = new ethers.Contract(tokens.ft, erc20Abi, provider);
  const xt = new ethers.Contract(tokens.xt, erc20Abi, provider);
  const gt = new ethers.Contract(tokens.gt, gtAbi, provider);
  const collateral = new ethers.Contract(tokens.collateral, erc20Abi, provider);
  const debt = new ethers.Contract(tokens.debtToken, erc20Abi, provider);
  const [
    gtConfig, gtSupply, ftSupply, xtSupply, ftMarketBalance, xtMarketBalance,
    debtMarketBalance, collateralGtBalance, debtSymbol, debtDecimals,
    collateralSymbol, collateralDecimals,
  ] = await Promise.all([
    gt.getGtConfig({ blockTag }),
    gt.totalSupply({ blockTag }),
    ft.totalSupply({ blockTag }),
    xt.totalSupply({ blockTag }),
    ft.balanceOf(base.market, { blockTag }),
    xt.balanceOf(base.market, { blockTag }),
    debt.balanceOf(base.market, { blockTag }),
    collateral.balanceOf(tokens.gt, { blockTag }),
    debt.symbol({ blockTag }).catch(() => ''),
    debt.decimals({ blockTag }),
    collateral.symbol({ blockTag }).catch(() => ''),
    collateral.decimals({ blockTag }),
  ]);
  return serialise({
    ...base,
    name,
    codeBytes: Math.max((code.length - 2) / 2, 0),
    codeHash: ethers.utils.keccak256(code),
    config,
    tokens,
    debtMeta: { symbol: debtSymbol, decimals: debtDecimals },
    collateralMeta: { symbol: collateralSymbol, decimals: collateralDecimals },
    balances: {
      gtSupply, ftSupply, xtSupply, ftMarketBalance, xtMarketBalance,
      debtMarketBalance, collateralGtBalance,
    },
    gtConfig,
    debtOracle: await oracleInfo(provider, gtConfig.loanConfig.oracle, tokens.debtToken, blockTag),
    collateralOracle: await oracleInfo(provider, gtConfig.loanConfig.oracle, tokens.collateral, blockTag),
  });
}

(async () => {
  fs.mkdirSync(OUT, { recursive: true });
  const { providers, attempts } = await discoverProviders();
  const stateEndpoint = providers[0];
  const provider = stateEndpoint.provider;
  const blockNumber = Math.min(...providers.map((x) => x.blockNumber));
  const block = await provider.getBlock(blockNumber);
  const marketMap = new Map();
  const scans = [];

  for (const factory of FACTORIES) {
    const code = await provider.getCode(factory.address, blockNumber).catch(() => '0x');
    const scan = await scanFactory(providers, factory, blockNumber);
    scans.push({
      factory: factory.address,
      fromBlock: factory.fromBlock,
      codeBytes: Math.max((code.length - 2) / 2, 0),
      rpc: scan.rpc,
      attempts: scan.attempts,
      progress: scan.progress,
      logCount: scan.logs.length,
      fatalError: scan.fatalError || null,
    });
    for (const log of scan.logs) {
      if (log.topics.length < 4) continue;
      const market = ethers.utils.getAddress(`0x${log.topics[1].slice(-40)}`);
      const collateralEvent = ethers.utils.getAddress(`0x${log.topics[2].slice(-40)}`);
      const debtEvent = ethers.utils.getAddress(`0x${log.topics[3].slice(-40)}`);
      marketMap.set(market.toLowerCase(), {
        market,
        factory: factory.address,
        createdBlock: log.blockNumber,
        createdTx: log.transactionHash,
        collateralEvent,
        debtEvent,
      });
    }
  }

  const markets = [];
  for (const base of marketMap.values()) {
    try {
      markets.push(await inspectMarket(provider, base, blockNumber));
    } catch (error) {
      markets.push({ ...base, fatalError: String(error) });
    }
  }

  const output = {
    label: LABEL,
    stateRpc: stateEndpoint.url,
    rpcAttempts: attempts,
    chainId: stateEndpoint.chainId,
    snapshot: { blockNumber, blockHash: block.hash, timestamp: block.timestamp },
    factories: scans,
    marketCount: markets.length,
    markets,
  };
  fs.writeFileSync(`${OUT}/all-market-inventory.json`, JSON.stringify(output, null, 2));
  console.log(JSON.stringify({
    label: LABEL,
    chainId: stateEndpoint.chainId,
    blockNumber,
    marketCount: markets.length,
    factories: scans.map((x) => ({ factory: x.factory, logCount: x.logCount, fatalError: x.fatalError })),
  }, null, 2));
})().catch((error) => {
  fs.mkdirSync(OUT, { recursive: true });
  fs.writeFileSync(`${OUT}/error.txt`, String(error.stack || error));
  console.error(error);
  process.exitCode = 0;
});
