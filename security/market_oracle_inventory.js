const fs = require('fs');
const { ethers } = require('ethers');

const LABEL = process.env.LABEL;
const RPCS = process.env.RPCS.split(',').map(x => x.trim()).filter(Boolean);
const MARKETS = process.env.MARKETS.split(',').map(x => ethers.utils.getAddress(x.trim()));
const OUT = 'encrypted-market-evidence';

const marketAbi = [
  'function name() view returns (string)',
  'function tokens() view returns (address ft,address xt,address gt,address collateral,address debtToken)',
  'function config() view returns (tuple(address treasurer,uint64 maturity,tuple(uint32 lendTakerFeeRatio,uint32 lendMakerFeeRatio,uint32 borrowTakerFeeRatio,uint32 borrowMakerFeeRatio,uint32 mintGtFeeRatio,uint32 mintGtFeeRef) feeConfig))'
];
const gtAbi = [
  'function getGtConfig() view returns (tuple(address collateral,address debtToken,address ft,address treasurer,uint64 maturity,tuple(address oracle,uint32 liquidationLtv,uint32 maxLtv,bool liquidatable) loanConfig))',
  'function totalSupply() view returns (uint256)'
];
const oracleAbi = [
  'function getPrice(address asset) view returns (uint256 price,uint8 decimals)',
  'function oracles(address asset) view returns (address aggregator,address backupAggregator,int256 maxPrice,int256 minPrice,uint32 heartbeat,uint32 backupHeartbeat)'
];
const erc20Abi = [
  'function symbol() view returns (string)',
  'function decimals() view returns (uint8)',
  'function totalSupply() view returns (uint256)',
  'function balanceOf(address) view returns (uint256)'
];
const feedAbi = [
  'function latestRoundData() view returns (uint80 roundId,int256 answer,uint256 startedAt,uint256 updatedAt,uint80 answeredInRound)',
  'function decimals() view returns (uint8)',
  'function description() view returns (string)',
  'function version() view returns (uint256)',
  'function pool() view returns (address)',
  'function twapPeriod() view returns (uint32)',
  'function baseToken() view returns (address)',
  'function quoteToken() view returns (address)',
  'function asset() view returns (address)',
  'function aTokenToBTokenPriceFeed() view returns (address)',
  'function bTokenToCTokenPriceFeed() view returns (address)',
  'function result() view returns (uint256)',
  'function pairIndex() view returns (uint256)',
  'function pharosOracle() view returns (address)',
  'function xaueOracle() view returns (address)'
];

async function chooseProvider() {
  const attempts = [];
  for (const url of RPCS) {
    try {
      const provider = new ethers.providers.JsonRpcProvider(url);
      const [network, blockNumber] = await Promise.all([provider.getNetwork(), provider.getBlockNumber()]);
      attempts.push({ url, ok: true, chainId: network.chainId, blockNumber });
      return { provider, url, attempts, chainId: network.chainId, blockNumber };
    } catch (error) {
      attempts.push({ url, ok: false, error: String(error) });
    }
  }
  throw new Error(`No working RPC: ${JSON.stringify(attempts)}`);
}

async function safe(promise) {
  try { return { ok: true, value: await promise }; }
  catch (error) { return { ok: false, error: String(error) }; }
}

function serialise(value) {
  if (ethers.BigNumber.isBigNumber(value)) return value.toString();
  if (Array.isArray(value)) return value.map(serialise);
  if (value && typeof value === 'object') {
    const out = {};
    for (const [key, item] of Object.entries(value)) if (!/^\d+$/.test(key)) out[key] = serialise(item);
    return out;
  }
  return value;
}

async function inspectFeed(provider, address, blockTag) {
  if (!address || address === ethers.constants.AddressZero) return null;
  const feed = new ethers.Contract(address, feedAbi, provider);
  const code = await provider.getCode(address, blockTag);
  const getters = {};
  for (const key of ['pool','twapPeriod','baseToken','quoteToken','asset','aTokenToBTokenPriceFeed','bTokenToCTokenPriceFeed','result','pairIndex','pharosOracle','xaueOracle']) {
    getters[key] = serialise(await safe(feed[key]({ blockTag })));
  }
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

async function inspectOracleSide(provider, oracleAddress, asset, blockTag) {
  const oracle = new ethers.Contract(oracleAddress, oracleAbi, provider);
  const config = await safe(oracle.oracles(asset, { blockTag }));
  const currentPrice = await safe(oracle.getPrice(asset, { blockTag }));
  if (!config.ok) return serialise({ oracleAddress, asset, config, currentPrice });
  const aggregator = config.value.aggregator;
  const backupAggregator = config.value.backupAggregator;
  return serialise({
    oracleAddress,
    asset,
    config,
    currentPrice,
    primary: await inspectFeed(provider, aggregator, blockTag),
    backup: await inspectFeed(provider, backupAggregator, blockTag)
  });
}

(async () => {
  fs.mkdirSync(OUT, { recursive: true });
  const { provider, url, attempts, chainId, blockNumber } = await chooseProvider();
  const block = await provider.getBlock(blockNumber);
  const results = [];
  for (const marketAddress of MARKETS) {
    const market = new ethers.Contract(marketAddress, marketAbi, provider);
    try {
      const [name, tokens, config, code] = await Promise.all([
        market.name({ blockTag: blockNumber }).catch(() => ''),
        market.tokens({ blockTag: blockNumber }),
        market.config({ blockTag: blockNumber }),
        provider.getCode(marketAddress, blockNumber)
      ]);
      const ft = new ethers.Contract(tokens.ft, erc20Abi, provider);
      const xt = new ethers.Contract(tokens.xt, erc20Abi, provider);
      const gt = new ethers.Contract(tokens.gt, gtAbi, provider);
      const collateral = new ethers.Contract(tokens.collateral, erc20Abi, provider);
      const debt = new ethers.Contract(tokens.debtToken, erc20Abi, provider);
      const [gtConfig, gtSupply, ftSupply, xtSupply, ftMarketBalance, xtMarketBalance, debtMarketBalance, collateralGtBalance, debtMeta, collateralMeta] = await Promise.all([
        gt.getGtConfig({ blockTag: blockNumber }),
        gt.totalSupply({ blockTag: blockNumber }),
        ft.totalSupply({ blockTag: blockNumber }),
        xt.totalSupply({ blockTag: blockNumber }),
        ft.balanceOf(marketAddress, { blockTag: blockNumber }),
        xt.balanceOf(marketAddress, { blockTag: blockNumber }),
        debt.balanceOf(marketAddress, { blockTag: blockNumber }),
        collateral.balanceOf(tokens.gt, { blockTag: blockNumber }),
        Promise.all([debt.symbol({ blockTag: blockNumber }).catch(()=>''), debt.decimals({ blockTag: blockNumber })]),
        Promise.all([collateral.symbol({ blockTag: blockNumber }).catch(()=>''), collateral.decimals({ blockTag: blockNumber })])
      ]);
      const oracleAddress = gtConfig.loanConfig.oracle;
      results.push(serialise({
        marketAddress,
        name,
        codeBytes: Math.max((code.length - 2) / 2, 0),
        codeHash: ethers.utils.keccak256(code),
        config,
        tokens,
        debtMeta: { symbol: debtMeta[0], decimals: debtMeta[1] },
        collateralMeta: { symbol: collateralMeta[0], decimals: collateralMeta[1] },
        balances: { gtSupply, ftSupply, xtSupply, ftMarketBalance, xtMarketBalance, debtMarketBalance, collateralGtBalance },
        gtConfig,
        debtOracle: await inspectOracleSide(provider, oracleAddress, tokens.debtToken, blockNumber),
        collateralOracle: await inspectOracleSide(provider, oracleAddress, tokens.collateral, blockNumber)
      }));
    } catch (error) {
      results.push({ marketAddress, fatalError: String(error) });
    }
  }
  const output = { label: LABEL, rpc: url, rpcAttempts: attempts, chainId, snapshot: { blockNumber, blockHash: block.hash, timestamp: block.timestamp }, markets: results };
  fs.writeFileSync(`${OUT}/market-oracle-inventory.json`, JSON.stringify(output, null, 2));
})().catch(error => {
  fs.mkdirSync(OUT, { recursive: true });
  fs.writeFileSync(`${OUT}/error.txt`, String(error.stack || error));
  process.exit(1);
});
