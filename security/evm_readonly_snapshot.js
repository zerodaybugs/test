const fs = require('fs');
const { ethers } = require('ethers');

const RPCS = [
  'https://ethereum-rpc.publicnode.com',
  'https://eth.llamarpc.com',
  'https://eth.drpc.org',
  'https://1rpc.io/eth',
];

const TARGETS = [
  {
    label: 'vault-a',
    vault: '0xF488ccdf04079cC03183cDB6A147d12Cf97F9317',
    orders: [
      '0xDfbf38D4d891599162E7b98dd21A1a6260a85Cab',
      '0x3693B342e4488b404232B60f4BE57233EE2a341b',
      '0x667DDd85358E8765814f07efd1C4A9caD67521d7',
      '0x93257038eCc1337D296eC61B2629704fe89acfa5',
      '0xe7059DdD2Dc6f7D54088628655D8C3A096804448',
      '0x66197a8bb9621a6DA48E9c28FD6f23341901af8d',
      '0xBfa722665E59dC7e31E07A5e5e862973d332d742',
      '0x69934e4a00133B566DD4853C65E254eA66544B34',
    ],
  },
  {
    label: 'vault-b',
    vault: '0x17337c22CF8b7C1B6fC86F0ef7Fcf05a7fA93f48',
    orders: [
      '0xC6A813476E2Bbc2EBbF444654b3D6e750473A397',
      '0xb40b652117Ad7782Db84036d07902a6c9530111b',
      '0xDad9be9aB9D089bA7135483671d758134a80c5C7',
    ],
  },
  {
    label: 'vault-c',
    vault: '0x7A84fCB839BEb377861001c6339a986B9e6d6D68',
    orders: [
      '0x3e35F030836CB93276C34b89DCF6A2D32759384B',
      '0x4619Cb0446DA38ee381E6FD15ab9161C134b2E18',
      '0x8c506C3D59219Fac4662995aac02BEdC29b0a6aa',
      '0x667c16Eef2D2a904DCa777432b83cb502124869b',
    ],
  },
  {
    label: 'vault-d',
    vault: '0x95fB87609f80c47e3102B976455023D2B9BE9b8F',
    orders: ['0x562046484a1F9128836Bb265801C4039DABD6b7E'],
  },
];

const vaultAbi = [
  'function name() view returns (string)',
  'function symbol() view returns (string)',
  'function asset() view returns (address)',
  'function totalAssets() view returns (uint256)',
  'function totalSupply() view returns (uint256)',
  'function paused() view returns (bool)',
  'function maxDeposit(address) view returns (uint256)',
  'function previewWithdraw(uint256) view returns (uint256)',
  'function orderMaturity(address) view returns (uint256)',
  'function badDebtMapping(address) view returns (uint256)',
];
const orderAbi = [
  'function market() view returns (address)',
  'function tokenReserves() view returns (uint256 ftReserve,uint256 xtReserve)',
  'function getRealReserves() view returns (uint256 ftReserve,uint256 xtReserve)',
  'function virtualXtReserve() view returns (uint256)',
  'function orderExpiryTimestamp() view returns (uint256)',
];
const marketAbi = [
  'function tokens() view returns (address ft,address xt,address gt,address collateral,address debtToken)',
  'function config() view returns (tuple(address treasurer,uint64 maturity,tuple(uint32 lendTakerFeeRatio,uint32 lendMakerFeeRatio,uint32 borrowTakerFeeRatio,uint32 borrowMakerFeeRatio,uint32 mintGtFeeRatio,uint32 mintGtFeeRef) feeConfig))',
  'function previewRedeem(uint256 ftAmount) view returns (uint256 debtTokenAmt,bytes deliveryData)',
];
const erc20Abi = [
  'function balanceOf(address) view returns (uint256)',
  'function totalSupply() view returns (uint256)',
  'function decimals() view returns (uint8)',
  'function symbol() view returns (string)',
];
const gtAbi = [
  'function liquidatable() view returns (bool)',
  'function previewDelivery(uint256 proportion) view returns (bytes)',
  'function getCollateralValue(bytes collateralData) view returns (uint256)',
  'function getGtConfig() view returns (tuple(address collateral,address debtToken,address ft,address treasurer,uint64 maturity,tuple(address oracle,uint32 liquidationLtv,uint32 maxLtv,bool liquidatable) loanConfig))',
];
const oracleAbi = ['function getPrice(address asset) view returns (uint256 price,uint8 decimals)'];

const BASE8 = ethers.BigNumber.from('100000000');
const BASE16 = ethers.BigNumber.from('10000000000000000');

async function chooseProvider() {
  const attempts = [];
  for (const url of RPCS) {
    try {
      const provider = new ethers.providers.JsonRpcProvider(url, 1);
      const [network, blockNumber] = await Promise.all([provider.getNetwork(), provider.getBlockNumber()]);
      if (network.chainId !== 1) throw new Error(`unexpected chain ${network.chainId}`);
      attempts.push({ url, ok: true, blockNumber });
      return { provider, url, attempts };
    } catch (error) {
      attempts.push({ url, ok: false, error: String(error) });
    }
  }
  throw new Error(`No usable RPC: ${JSON.stringify(attempts)}`);
}

async function safe(promise) {
  try {
    return { ok: true, value: await promise };
  } catch (error) {
    return { ok: false, error: String(error) };
  }
}

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

function safeSub(a, b) {
  return a.gte(b) ? a.sub(b) : ethers.constants.Zero;
}

async function inspectOrder(provider, vault, orderAddress, blockTag) {
  const order = new ethers.Contract(orderAddress, orderAbi, provider);
  const marketAddress = await order.market({ blockTag });
  const market = new ethers.Contract(marketAddress, marketAbi, provider);
  const tokens = await market.tokens({ blockTag });
  const ftAddress = tokens.ft;
  const gtAddress = tokens.gt;
  const collateralAddress = tokens.collateral;
  const debtAddress = tokens.debtToken;
  const ft = new ethers.Contract(ftAddress, erc20Abi, provider);
  const gt = new ethers.Contract(gtAddress, gtAbi, provider);
  const debt = new ethers.Contract(debtAddress, erc20Abi, provider);
  const collateral = new ethers.Contract(collateralAddress, erc20Abi, provider);

  const [
    ftBalance,
    ftSupply,
    ftMarketBalance,
    debtMarketBalance,
    debtDecimals,
    collateralDecimals,
    debtSymbol,
    collateralSymbol,
    tokenReserves,
    realReserves,
    virtualXtReserve,
    expiry,
    orderMaturity,
    badDebt,
    liquidatable,
    gtConfig,
    marketConfig,
  ] = await Promise.all([
    ft.balanceOf(orderAddress, { blockTag }),
    ft.totalSupply({ blockTag }),
    ft.balanceOf(marketAddress, { blockTag }),
    debt.balanceOf(marketAddress, { blockTag }),
    debt.decimals({ blockTag }),
    collateral.decimals({ blockTag }),
    debt.symbol({ blockTag }).catch(() => ''),
    collateral.symbol({ blockTag }).catch(() => ''),
    order.tokenReserves({ blockTag }),
    order.getRealReserves({ blockTag }).catch(() => null),
    order.virtualXtReserve({ blockTag }).catch(() => ethers.constants.Zero),
    order.orderExpiryTimestamp({ blockTag }).catch(() => ethers.constants.Zero),
    vault.orderMaturity(orderAddress, { blockTag }).catch(() => ethers.constants.Zero),
    vault.badDebtMapping(collateralAddress, { blockTag }).catch(() => ethers.constants.Zero),
    gt.liquidatable({ blockTag }),
    gt.getGtConfig({ blockTag }),
    market.config({ blockTag }),
  ]);

  const oracleAddress = gtConfig.loanConfig.oracle;
  const oracle = new ethers.Contract(oracleAddress, oracleAbi, provider);
  const [debtPriceResult, collateralPriceResult] = await Promise.all([
    oracle.getPrice(debtAddress, { blockTag }),
    oracle.getPrice(collateralAddress, { blockTag }),
  ]);

  const netFtSupply = safeSub(ftSupply, ftMarketBalance);
  let derived = null;
  if (!ftBalance.isZero() && !netFtSupply.isZero()) {
    const proportion = ftBalance.mul(BASE16).div(netFtSupply);
    const previewDelivery = await safe(gt.previewDelivery(proportion, { blockTag }));
    let collateralValueBase8 = ethers.constants.Zero;
    if (previewDelivery.ok) {
      const collateralValue = await safe(gt.getCollateralValue(previewDelivery.value, { blockTag }));
      if (collateralValue.ok) collateralValueBase8 = collateralValue.value;
    }
    const debtOut = debtMarketBalance.mul(proportion).div(BASE16);
    const debtDenominator = ethers.BigNumber.from(10).pow(debtDecimals);
    const debtPriceDenominator = ethers.BigNumber.from(10).pow(debtPriceResult.decimals);
    const debtValueBase8 = debtOut.mul(debtPriceResult.price).mul(BASE8).div(debtDenominator.mul(debtPriceDenominator));
    const totalValueBase8 = debtValueBase8.add(collateralValueBase8);
    const faceValueBase8 = ftBalance.mul(debtPriceResult.price).mul(BASE8).div(debtDenominator.mul(debtPriceDenominator));
    const recoveryRatioPpm = faceValueBase8.isZero() ? null : totalValueBase8.mul(1_000_000).div(faceValueBase8);
    const previewRedeem = await safe(market.previewRedeem(ftBalance, { blockTag }));
    derived = {
      proportion,
      previewDelivery,
      collateralValueBase8,
      debtOut,
      debtValueBase8,
      totalValueBase8,
      faceValueBase8,
      recoveryRatioPpm,
      previewRedeem,
    };
  }

  return serialise({
    orderAddress,
    marketAddress,
    tokens,
    debtSymbol,
    collateralSymbol,
    debtDecimals,
    collateralDecimals,
    ftBalance,
    ftSupply,
    ftMarketBalance,
    netFtSupply,
    debtMarketBalance,
    tokenReserves,
    realReserves,
    virtualXtReserve,
    expiry,
    orderMaturity,
    badDebt,
    liquidatable,
    gtConfig,
    marketConfig,
    debtPriceResult,
    collateralPriceResult,
    derived,
  });
}

(async () => {
  const { provider, url, attempts } = await chooseProvider();
  const blockNumber = await provider.getBlockNumber();
  const block = await provider.getBlock(blockNumber);
  const result = {
    rpc: url,
    rpcAttempts: attempts,
    snapshot: { blockNumber, blockHash: block.hash, timestamp: block.timestamp },
    targets: [],
  };

  for (const target of TARGETS) {
    const vaultAddress = ethers.utils.getAddress(target.vault);
    const vault = new ethers.Contract(vaultAddress, vaultAbi, provider);
    const assetAddress = await vault.asset({ blockTag: blockNumber });
    const asset = new ethers.Contract(assetAddress, erc20Abi, provider);
    const [name, symbol, decimals, totalAssets, totalSupply, paused, maxDeposit] = await Promise.all([
      vault.name({ blockTag: blockNumber }),
      vault.symbol({ blockTag: blockNumber }),
      asset.decimals({ blockTag: blockNumber }),
      vault.totalAssets({ blockTag: blockNumber }),
      vault.totalSupply({ blockTag: blockNumber }),
      vault.paused({ blockTag: blockNumber }),
      vault.maxDeposit(vaultAddress, { blockTag: blockNumber }),
    ]);
    const orders = [];
    for (const orderAddress of target.orders) {
      try {
        orders.push(await inspectOrder(provider, vault, ethers.utils.getAddress(orderAddress), blockNumber));
      } catch (error) {
        orders.push({ orderAddress, fatalError: String(error) });
      }
    }
    result.targets.push(serialise({
      label: target.label,
      vaultAddress,
      name,
      symbol,
      assetAddress,
      decimals,
      totalAssets,
      totalSupply,
      paused,
      maxDeposit,
      orders,
    }));
  }

  fs.mkdirSync('encrypted-evidence', { recursive: true });
  fs.writeFileSync('encrypted-evidence/snapshot.json', JSON.stringify(result, null, 2));
})().catch((error) => {
  fs.mkdirSync('encrypted-evidence', { recursive: true });
  fs.writeFileSync('encrypted-evidence/error.txt', String(error.stack || error));
  process.exit(1);
});
