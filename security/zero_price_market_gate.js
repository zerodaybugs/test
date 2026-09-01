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
const OUT = 'zero-price-gate';
const MARKET_TOPIC = '0x3f544a0e66146e1c515b04e3d00d07fabc299aa08db26f13ae0a2e3797503286';
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
const erc20Abi = [
  'function symbol() view returns(string)', 'function decimals() view returns(uint8)',
  'function totalSupply() view returns(uint256)', 'function balanceOf(address) view returns(uint256)'
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
  'function decimals() view returns(uint8)', 'function description() view returns(string)', 'function version() view returns(uint256)',
  'function pool() view returns(address)', 'function twapPeriod() view returns(uint32)',
  'function baseToken() view returns(address)', 'function quoteToken() view returns(address)', 'function asset() view returns(address)',
  'function PRICE_FEED() view returns(address)', 'function MARKET() view returns(address)', 'function DURATION() view returns(uint32)',
  'function aTokenToBTokenPriceFeed() view returns(address)', 'function bTokenToCTokenPriceFeed() view returns(address)',
  'function dusdOracle() view returns(address)', 'function uspcOracle() view returns(address)', 'function xaueOracle() view returns(address)',
  'function pharosOracle() view returns(address)', 'function ondoOracle() view returns(address)',
  'function result() view returns(uint256)', 'function pairIndex() view returns(uint256)'
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
async function safe(p) { try { return { ok: true, value: ser(await p) }; } catch (e) { return { ok: false, error: String(e) }; } }
async function chooseProvider() {
  const attempts = [];
  for (const url of RPCS) {
    try {
      const provider = new ethers.providers.JsonRpcProvider(url);
      const [network, blockNumber] = await Promise.all([provider.getNetwork(), provider.getBlockNumber()]);
      attempts.push({ url, ok: true, chainId: network.chainId, blockNumber });
      return { provider, url, chainId: network.chainId, blockNumber, attempts };
    } catch (e) { attempts.push({ url, ok: false, error: String(e) }); }
  }
  throw new Error(`no working RPC: ${JSON.stringify(attempts)}`);
}
function normalizeLog(l) {
  return {
    topics: l.topics || [l.topic0, l.topic1, l.topic2, l.topic3].filter(Boolean),
    blockNumber: Number(l.blockNumber || l.block_number || 0),
    transactionHash: l.transactionHash || l.transaction_hash || ''
  };
}
async function directLogs(provider, target, fromBlock, toBlock) {
  let current = fromBlock;
  let span = 100000;
  const logs = [];
  while (current <= toBlock) {
    const end = Math.min(toBlock, current + span - 1);
    try {
      const part = await provider.getLogs({ address: target, fromBlock: current, toBlock: end, topics: [MARKET_TOPIC] });
      logs.push(...part);
      current = end + 1;
      if (part.length < 100 && span < 500000) span = Math.min(500000, span * 2);
    } catch (e) {
      if (span <= 100) throw e;
      span = Math.max(100, Math.floor(span / 2));
    }
  }
  return logs.map(normalizeLog);
}
async function indexedLogs(target, fromBlock, toBlock) {
  const response = await sdk.api.util.getLogs({ chain: CHAIN, target, topic: MARKET_TOPIC, fromBlock, toBlock });
  return (response.output || []).map(normalizeLog);
}
async function marketLogs(provider, factory, toBlock) {
  const attempts = [];
  try {
    const logs = await directLogs(provider, factory.address, factory.fromBlock, toBlock);
    attempts.push({ source: 'rpc', ok: true, count: logs.length });
    return { logs, attempts, source: 'rpc' };
  } catch (e) { attempts.push({ source: 'rpc', ok: false, error: String(e) }); }
  try {
    const logs = await indexedLogs(factory.address, factory.fromBlock, toBlock);
    attempts.push({ source: 'defillama', ok: true, count: logs.length });
    return { logs, attempts, source: 'defillama' };
  } catch (e) {
    attempts.push({ source: 'defillama', ok: false, error: String(e) });
    return { logs: [], attempts, source: null, fatalError: 'all log sources failed' };
  }
}
async function feedInfo(provider, address, blockTag) {
  if (!address || address === ethers.constants.AddressZero) return null;
  const feed = new ethers.Contract(address, feedAbi, provider);
  const code = await provider.getCode(address, blockTag);
  const getters = {};
  for (const key of ['pool','twapPeriod','baseToken','quoteToken','asset','PRICE_FEED','MARKET','DURATION','aTokenToBTokenPriceFeed','bTokenToCTokenPriceFeed','dusdOracle','uspcOracle','xaueOracle','pharosOracle','ondoOracle','result','pairIndex']) {
    getters[key] = await safe(feed[key]({ blockTag }));
  }
  return ser({
    address, codeHash: ethers.utils.keccak256(code), codeBytes: (code.length - 2) / 2,
    latestRoundData: await safe(feed.latestRoundData({ blockTag })),
    decimals: await safe(feed.decimals({ blockTag })),
    description: await safe(feed.description({ blockTag })),
    version: await safe(feed.version({ blockTag })), getters
  });
}
async function oracleInfo(provider, address, asset, blockTag) {
  const v2 = new ethers.Contract(address, oracleV2Abi, provider);
  const configV2 = await safe(v2.oracles(asset, { blockTag }));
  if (configV2.ok) {
    const c = configV2.value;
    return ser({ shape: 'V2', address, asset, config: configV2,
      current: await safe(v2.getPrice(asset, { blockTag })),
      primary: await feedInfo(provider, c.aggregator, blockTag),
      backup: await feedInfo(provider, c.backupAggregator, blockTag) });
  }
  const v1 = new ethers.Contract(address, oracleV1Abi, provider);
  const configV1 = await safe(v1.oracles(asset, { blockTag }));
  return ser({ shape: configV1.ok ? 'V1' : 'unknown', address, asset, config: configV1,
    current: await safe(v1.getPrice(asset, { blockTag })),
    primary: configV1.ok ? await feedInfo(provider, configV1.value.aggregator, blockTag) : null,
    backup: configV1.ok ? await feedInfo(provider, configV1.value.backupAggregator, blockTag) : null });
}
(async () => {
  fs.mkdirSync(OUT, { recursive: true });
  const { provider, url, chainId, blockNumber, attempts } = await chooseProvider();
  const block = await provider.getBlock(blockNumber);
  const map = new Map();
  const factoryScans = [];
  for (const factory of FACTORIES) {
    const scan = await marketLogs(provider, factory, blockNumber);
    factoryScans.push({ ...factory, source: scan.source, attempts: scan.attempts, count: scan.logs.length, fatalError: scan.fatalError || null });
    for (const l of scan.logs) {
      if (!l.topics || l.topics.length < 4) continue;
      const market = ethers.utils.getAddress(`0x${l.topics[1].slice(-40)}`);
      map.set(market.toLowerCase(), { market, factory: factory.address, createdBlock: l.blockNumber, createdTx: l.transactionHash,
        collateralEvent: ethers.utils.getAddress(`0x${l.topics[2].slice(-40)}`), debtEvent: ethers.utils.getAddress(`0x${l.topics[3].slice(-40)}`) });
    }
  }
  const markets = [];
  for (const base of map.values()) {
    try {
      const market = new ethers.Contract(base.market, marketAbi, provider);
      const [name, tokens, config, isOpen, code] = await Promise.all([
        market.name({ blockTag: blockNumber }).catch(() => ''), market.tokens({ blockTag: blockNumber }),
        market.config({ blockTag: blockNumber }), market.isOpen({ blockTag: blockNumber }).catch(() => null),
        provider.getCode(base.market, blockNumber)
      ]);
      const ft = new ethers.Contract(tokens.ft, erc20Abi, provider);
      const xt = new ethers.Contract(tokens.xt, erc20Abi, provider);
      const gt = new ethers.Contract(tokens.gt, gtAbi, provider);
      const debt = new ethers.Contract(tokens.debtToken, erc20Abi, provider);
      const collateral = new ethers.Contract(tokens.collateral, erc20Abi, provider);
      const [gtConfig, ftSupply, xtSupply, gtSupply, debtMarketBalance, collateralGtBalance, debtSymbol, debtDecimals, collateralSymbol, collateralDecimals] = await Promise.all([
        gt.getGtConfig({ blockTag: blockNumber }), ft.totalSupply({ blockTag: blockNumber }), xt.totalSupply({ blockTag: blockNumber }), gt.totalSupply({ blockTag: blockNumber }),
        debt.balanceOf(base.market, { blockTag: blockNumber }), collateral.balanceOf(tokens.gt, { blockTag: blockNumber }),
        debt.symbol({ blockTag: blockNumber }).catch(() => ''), debt.decimals({ blockTag: blockNumber }),
        collateral.symbol({ blockTag: blockNumber }).catch(() => ''), collateral.decimals({ blockTag: blockNumber })
      ]);
      const debtOracle = await oracleInfo(provider, gtConfig.loanConfig.oracle, tokens.debtToken, blockNumber);
      const debtConfig = debtOracle.shape === 'V2' && debtOracle.config.ok ? debtOracle.config.value : null;
      const primaryAnswer = debtOracle.primary?.latestRoundData?.ok ? debtOracle.primary.latestRoundData.value.answer : null;
      markets.push(ser({ ...base, name, codeHash: ethers.utils.keccak256(code), isOpen, config, tokens,
        debtMeta: { symbol: debtSymbol, decimals: debtDecimals }, collateralMeta: { symbol: collateralSymbol, decimals: collateralDecimals },
        balances: { ftSupply, xtSupply, gtSupply, debtMarketBalance, collateralGtBalance }, gtConfig, debtOracle,
        gates: { maturityFuture: Number(gtConfig.maturity) > block.timestamp, v2Oracle: debtOracle.shape === 'V2',
          minPriceZero: debtConfig ? String(debtConfig.minPrice) === '0' : false,
          currentPriceZero: debtOracle.current.ok ? String(debtOracle.current.value[0] || debtOracle.current.value.price || '') === '0' : false,
          primaryAnswerZero: primaryAnswer != null ? String(primaryAnswer) === '0' : false,
          nonzeroSupply: !ftSupply.isZero() || !xtSupply.isZero() || !gtSupply.isZero(), nonzeroMarketDebt: !debtMarketBalance.isZero() }
      }));
    } catch (e) { markets.push({ ...base, fatalError: String(e) }); }
  }
  const output = { label: LABEL, chain: CHAIN, rpc: url, rpcAttempts: attempts, chainId,
    snapshot: { blockNumber, blockHash: block.hash, timestamp: block.timestamp }, factoryScans, marketCount: markets.length, markets };
  fs.writeFileSync(`${OUT}/zero-price-market-gate.json`, JSON.stringify(output, null, 2));
  console.log(JSON.stringify({ label: LABEL, chain: CHAIN, blockNumber, marketCount: markets.length,
    candidates: markets.filter(m => m.gates?.v2Oracle && m.gates?.minPriceZero && m.gates?.maturityFuture && (m.gates?.nonzeroSupply || m.gates?.nonzeroMarketDebt)).map(m => ({ market: m.market, name: m.name, debt: m.debtMeta?.symbol, gates: m.gates })) }, null, 2));
})().catch(e => { fs.mkdirSync(OUT, { recursive: true }); fs.writeFileSync(`${OUT}/error.txt`, String(e.stack || e)); console.error(e); process.exit(1); });
