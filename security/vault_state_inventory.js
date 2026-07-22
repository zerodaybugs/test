'use strict';

const fs = require('fs');
const { ethers } = require('ethers');

const OUT = 'encrypted-vault-state';
const RPCS = [
  'https://ethereum-rpc.publicnode.com',
  'https://eth.llamarpc.com',
  'https://eth.drpc.org',
  'https://1rpc.io/eth',
];
const VAULTS = [
  ['vault-a', '0xF488ccdf04079cC03183cDB6A147d12Cf97F9317', 23490022],
  ['vault-b', '0x17337c22CF8b7C1B6fC86F0ef7Fcf05a7fA93f48', 23516443],
  ['vault-c', '0x95fB87609f80c47e3102B976455023D2B9BE9b8F', 23490023],
  ['vault-d', '0x7A84fCB839BEb377861001c6339a986B9e6d6D68', 24338283],
  ['vault-e', '0x7fB02AeA6f04d44a61E413FA220CaF18DCD626Fb', 24832207],
  ['vault-f', '0x394ec054e8275C40c45F116683f250a3E40Ea34d', 24036283],
  ['vault-g', '0xBbf747e83f2f1650F7B303F6166Fc3fE8a5B0cE5', 23540487],
  ['vault-h', '0xE3e545abfA18019bcd74abA2C13dC569d6D018A8', 24832165],
];
const vaultAbi = [
  'function name() view returns(string)',
  'function asset() view returns(address)',
  'function pool() view returns(address)',
  'function curator() view returns(address)',
  'function performanceFeeRate() view returns(uint64)',
  'function performanceFee() view returns(uint256)',
  'function accretingPrincipal() view returns(uint256)',
  'function totalFt() view returns(uint256)',
  'function totalAssets() view returns(uint256)',
  'function totalSupply() view returns(uint256)',
  'function paused() view returns(bool)',
  'function maxDeposit(address) view returns(uint256)',
  'function badDebtMapping(address) view returns(uint256)',
  'event NewOrderCreated(address indexed caller,address indexed market,address indexed order)',
  'event RedeemOrder(address indexed caller,address indexed order,uint256 badDebt,uint256 diliveryAmount)',
  'event WithdrawPerformanceFee(address indexed caller,address indexed recipient,uint256 amount)',
];
const orderAbi = ['function market() view returns(address)'];
const marketAbi = [
  'function name() view returns(string)',
  'function tokens() view returns(address ft,address xt,address gt,address collateral,address debtToken)',
  'function config() view returns(tuple(address treasurer,uint64 maturity,tuple(uint32 lendTakerFeeRatio,uint32 lendMakerFeeRatio,uint32 borrowTakerFeeRatio,uint32 borrowMakerFeeRatio,uint32 mintGtFeeRatio,uint32 mintGtFeeRef) feeConfig))',
];
const erc20Abi = [
  'function symbol() view returns(string)',
  'function decimals() view returns(uint8)',
  'function balanceOf(address) view returns(uint256)',
];
const poolAbi = [
  'function maxWithdraw(address) view returns(uint256)',
  'function balanceOf(address) view returns(uint256)',
];

function ser(x) {
  if (ethers.BigNumber.isBigNumber(x)) return x.toString();
  if (Array.isArray(x)) return x.map(ser);
  if (x && typeof x === 'object') {
    const out = {};
    for (const [k, v] of Object.entries(x)) if (!/^\d+$/.test(k)) out[k] = ser(v);
    return out;
  }
  return x;
}
async function safe(p) { try { return { ok: true, value: ser(await p) }; } catch (e) { return { ok: false, error: String(e) }; } }
async function provider() {
  const attempts = [];
  for (const url of RPCS) {
    try {
      const p = new ethers.providers.JsonRpcProvider(url, 1);
      const [n, b] = await Promise.all([p.getNetwork(), p.getBlockNumber()]);
      if (n.chainId !== 1) throw new Error(`wrong chain ${n.chainId}`);
      attempts.push({ url, ok: true, block: b });
      return { p, url, block: b, attempts };
    } catch (e) { attempts.push({ url, ok: false, error: String(e) }); }
  }
  throw new Error(JSON.stringify(attempts));
}
async function logs(p, address, from, to, topics) {
  const out = [], progress = [];
  let cur = from, span = 100000;
  while (cur <= to) {
    const end = Math.min(to, cur + span - 1);
    try {
      const part = await p.getLogs({ address, fromBlock: cur, toBlock: end, topics: [topics] });
      out.push(...part); progress.push({ from: cur, to: end, count: part.length, span });
      cur = end + 1;
      if (part.length < 100 && span < 500000) span = Math.min(500000, span * 2);
    } catch (e) {
      progress.push({ from: cur, to: end, span, error: String(e) });
      if (span <= 500) throw e;
      span = Math.max(500, Math.floor(span / 2));
    }
  }
  return { out, progress };
}
async function inspect(p, label, rawAddress, fromBlock, block) {
  const address = ethers.utils.getAddress(rawAddress);
  const v = new ethers.Contract(address, vaultAbi, p);
  const iface = v.interface;
  const scan = await logs(p, address, fromBlock, block, [
    iface.getEventTopic('NewOrderCreated'),
    iface.getEventTopic('RedeemOrder'),
    iface.getEventTopic('WithdrawPerformanceFee'),
  ]);
  const orders = new Map(), redemptions = [], feeWithdrawals = [];
  for (const log of scan.out) {
    let x; try { x = iface.parseLog(log); } catch (_) { continue; }
    if (x.name === 'NewOrderCreated') orders.set(x.args.order.toLowerCase(), { order: x.args.order, marketEvent: x.args.market, block: log.blockNumber, tx: log.transactionHash });
    if (x.name === 'RedeemOrder') redemptions.push({ order: x.args.order, badDebt: x.args.badDebt.toString(), delivery: x.args.diliveryAmount.toString(), block: log.blockNumber, tx: log.transactionHash });
    if (x.name === 'WithdrawPerformanceFee') feeWithdrawals.push({ amount: x.args.amount.toString(), block: log.blockNumber, tx: log.transactionHash });
  }
  const [name, asset, pool, curator, rate, fee, principal, totalFt, totalAssets, totalSupply, paused, maxDeposit, code] = await Promise.all([
    v.name({ blockTag: block }).catch(() => ''), v.asset({ blockTag: block }), v.pool({ blockTag: block }).catch(() => ethers.constants.AddressZero),
    v.curator({ blockTag: block }).catch(() => ethers.constants.AddressZero), v.performanceFeeRate({ blockTag: block }), v.performanceFee({ blockTag: block }),
    v.accretingPrincipal({ blockTag: block }), v.totalFt({ blockTag: block }), v.totalAssets({ blockTag: block }), v.totalSupply({ blockTag: block }),
    v.paused({ blockTag: block }), v.maxDeposit(address, { blockTag: block }), p.getCode(address, block),
  ]);
  const token = new ethers.Contract(asset, erc20Abi, p);
  const [assetSymbol, assetDecimals, directCash] = await Promise.all([
    token.symbol({ blockTag: block }).catch(() => ''), token.decimals({ blockTag: block }), token.balanceOf(address, { blockTag: block }),
  ]);
  let poolWithdraw = ethers.constants.Zero, poolState = null;
  if (pool !== ethers.constants.AddressZero) {
    const pc = new ethers.Contract(pool, poolAbi, p);
    const mw = await safe(pc.maxWithdraw(address, { blockTag: block }));
    if (mw.ok) poolWithdraw = ethers.BigNumber.from(mw.value);
    poolState = { address: pool, maxWithdraw: mw, shares: await safe(pc.balanceOf(address, { blockTag: block })) };
  }
  const orderStates = [], collaterals = new Map();
  for (const base of orders.values()) {
    try {
      const order = new ethers.Contract(base.order, orderAbi, p);
      const marketAddress = await order.market({ blockTag: block });
      const market = new ethers.Contract(marketAddress, marketAbi, p);
      const [marketName, tokens, config] = await Promise.all([
        market.name({ blockTag: block }).catch(() => ''), market.tokens({ blockTag: block }), market.config({ blockTag: block }),
      ]);
      const c = ethers.utils.getAddress(tokens.collateral);
      collaterals.set(c.toLowerCase(), c);
      orderStates.push(ser({ ...base, market: marketAddress, marketName, collateral: c, debt: tokens.debtToken, maturity: config.maturity }));
    } catch (e) { orderStates.push({ ...base, error: String(e) }); }
  }
  const badDebts = [];
  let totalBadDebt = ethers.constants.Zero;
  for (const c of collaterals.values()) {
    const ct = new ethers.Contract(c, erc20Abi, p);
    const [amount, balance, symbol] = await Promise.all([
      v.badDebtMapping(c, { blockTag: block }), ct.balanceOf(address, { blockTag: block }), ct.symbol({ blockTag: block }).catch(() => ''),
    ]);
    totalBadDebt = totalBadDebt.add(amount);
    badDebts.push({ collateral: c, symbol, amount: amount.toString(), balance: balance.toString() });
  }
  const actualCash = directCash.add(poolWithdraw);
  return ser({
    label, address, fromBlock, name, codeHash: ethers.utils.keccak256(code), asset: { address: asset, symbol: assetSymbol, decimals: assetDecimals },
    curator, pool: poolState,
    accounting: { performanceFeeRate: rate, performanceFee: fee, accretingPrincipal: principal, totalFt, totalAssets, totalSupply, directCash, actualCash, totalBadDebt, paused, maxDeposit },
    eventScan: { count: scan.out.length, progress: scan.progress }, orderCount: orderStates.length, orders: orderStates, badDebts, redemptions, feeWithdrawals,
  });
}

(async () => {
  fs.mkdirSync(OUT, { recursive: true });
  const { p, url, block, attempts } = await provider();
  const header = await p.getBlock(block);
  const vaults = [];
  for (const [label, address, from] of VAULTS) {
    try { vaults.push(await inspect(p, label, address, from, block)); }
    catch (e) { vaults.push({ label, address, fatalError: String(e) }); }
  }
  const result = { generatedAt: new Date().toISOString(), scope: 'READ-ONLY', rpc: url, rpcAttempts: attempts, snapshot: { block, hash: header.hash, timestamp: header.timestamp }, vaults };
  fs.writeFileSync(`${OUT}/vault-state.json`, JSON.stringify(result, null, 2));
  fs.writeFileSync(`${OUT}/summary.json`, JSON.stringify({ snapshot: result.snapshot, vaults: vaults.map(v => ({ label: v.label, address: v.address, accounting: v.accounting, orderCount: v.orderCount, badDebts: v.badDebts, fatalError: v.fatalError })) }, null, 2));
  console.log(fs.readFileSync(`${OUT}/summary.json`, 'utf8'));
})().catch((e) => { fs.mkdirSync(OUT, { recursive: true }); fs.writeFileSync(`${OUT}/error.txt`, String(e.stack || e)); console.error(e); process.exit(1); });
