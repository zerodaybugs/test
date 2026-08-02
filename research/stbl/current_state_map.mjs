import fs from 'node:fs';
import path from 'node:path';
import {
  Contract,
  Interface,
  JsonRpcProvider,
  ZeroAddress,
  getAddress,
  id,
  keccak256,
  toUtf8Bytes,
} from 'ethers';

const OUT = path.resolve('evidence-stbl-state');
fs.mkdirSync(OUT, { recursive: true });

const TARGETS = [
  { chain: 'ethereum', label: 'STBL_Token_ETH', address: '0xb3116013c55d49f575ace3cb0d123f3dbf6cac35' },
  { chain: 'bsc', label: 'STBL_Token_BSC', address: '0x8dedf84656fa932157e27c060d8613824e7979e3' },
  { chain: 'ethereum', label: 'USST_ETH', address: '0xf9d82660828d8f5d121b14a9dc9c677d91f60065' },
  { chain: 'ethereum', label: 'YLD_ETH', address: '0xd33c37a90155be8fcab769e38a563e74bfd70e0b' },
  { chain: 'ethereum', label: 'Register_ETH', address: '0xa58b634c10df2665a3de1680675d5bb9065847d2' },
  { chain: 'ethereum', label: 'Core_ETH', address: '0x3c316bcf47c991ba09622d4c2f40f786ab4f46db' },
  { chain: 'ethereum', label: 'PT1_USDY_Issuer', address: '0xa0e2b352118f9983f3a75ddc9abd996983c93764' },
  { chain: 'ethereum', label: 'PT1_USDY_Vault', address: '0xd238e964b557bd8f39feba8c2c93d6f428007232' },
  { chain: 'ethereum', label: 'PT1_USDY_YD', address: '0x97fb98a7a7400bc651dec6a02640a36f8bdfaa0b' },
  { chain: 'ethereum', label: 'LT1_USDY_Issuer', address: '0x916442ebaa1cef4b3f5cd9b7a62170b50c3305c1' },
  { chain: 'ethereum', label: 'LT1_USDY_Vault', address: '0x5766b5d21bea4de3dda1b935f1740d194babab1f' },
  { chain: 'ethereum', label: 'LT1_USDY_YD', address: '0xcc14f2eddeae2a3c450c7afe328fd7331355dd73' },
  { chain: 'ethereum', label: 'PT1_OUSG_Issuer', address: '0xf8acf255854c8d36010c849f1702eb350c8c4087' },
  { chain: 'ethereum', label: 'PT1_OUSG_Vault', address: '0x64bef4478942d8fd62be281707076442aa2d055e' },
  { chain: 'ethereum', label: 'PT1_OUSG_YD', address: '0x447a8f3608fb2002c1aa8e44b076b7d62b6fa618' },
  { chain: 'ethereum', label: 'LT1_OUSG_Issuer', address: '0xbac1f4f20847669ba12841a534b2aa053d65373c' },
  { chain: 'ethereum', label: 'LT1_OUSG_Vault', address: '0x0437ee84ca723ceb7052a8cc73360e21427c42ea' },
  { chain: 'ethereum', label: 'LT1_OUSG_YD', address: '0x50eda4294d9a57b35a9d836faaeb88d1c4fab6c9' },
  { chain: 'bsc', label: 'USST_BSC', address: '0x1171ce10262a60c17507580a3b70b956f20a35de' },
];

const RPCS = {
  ethereum: [
    'https://ethereum-rpc.publicnode.com',
    'https://eth.llamarpc.com',
    'https://rpc.mevblocker.io',
    'https://1rpc.io/eth',
  ],
  bsc: [
    'https://bsc-rpc.publicnode.com',
    'https://bsc-dataseed.binance.org',
    'https://1rpc.io/bnb',
  ],
};

const EXPECTED_CHAIN_IDS = { ethereum: 1n, bsc: 56n };
const IMPLEMENTATION_SLOT = '0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc';
const ADMIN_SLOT = '0xb53127684a568b3173ae13b9f8a6016e019000000000000000000000000000000';
const ADMIN_SLOT_CANONICAL = '0xb53127684a568b3173ae13b9f8a6016e019a6a0f3a13e0a4f0f8f9a5f9e8d6a';
const BEACON_SLOT = '0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50';

const COMMON_ABI = [
  'function version() view returns (uint256)',
  'function trustedForwarder() view returns (address)',
  'function fetchRegistry() view returns (address)',
  'function fetchAssetID() view returns (uint256)',
  'function assetID() view returns (uint256)',
  'function registry() view returns (address)',
  'function totalSupply() view returns (uint256)',
  'function previousDistribution() view returns (uint256)',
  'function paused() view returns (bool)',
  'function nftCtr() view returns (uint256)',
  'function name() view returns (string)',
  'function symbol() view returns (string)',
  'function decimals() view returns (uint8)',
  'function balanceOf(address) view returns (uint256)',
  'function fetchVaultData() view returns ((uint256 depositFees,uint256 withdrawFees,uint256 insuranceFees,uint256 yieldFees,uint256 cumilativeHairCutValue,uint256 depositValueUSD,uint256 assetDepositGross,uint256 assetDepositNet))',
  'function getRoleAdmin(bytes32) view returns (bytes32)',
  'function hasRole(bytes32,address) view returns (bool)',
];

const REGISTRY_ABI = [
  ...COMMON_ABI,
  'function fetchCounter() view returns (uint256)',
  'function fetchUSSTToken() view returns (address)',
  'function fetchYLDToken() view returns (address)',
  'function fetchCore() view returns (address)',
  'function fetchTreasury() view returns (address)',
  'function fetchDeposits(uint256) view returns (uint256)',
  'function fetchAssetData(uint256) view returns ((uint256 id,string name,string description,uint8 contractType,bool isAggreagated,uint8 status,uint256 cut,uint256 limit,address token,address issuer,address rewardDistributor,address oracle,address vault,uint256 depositFees,uint256 withdrawFees,uint256 yieldFees,uint256 insuranceFees,uint256 duration,uint256 yieldDuration,bytes additionalBuffer))',
];

const ORACLE_ABI = [
  'function fetchPrice() view returns (uint256)',
  'function fetchPriceDecimals() view returns (uint256)',
  'function getPriceDecimals() view returns (uint256)',
  'function priceDecimals() view returns (uint256)',
  'function fetchPriceThreshold() view returns (uint256)',
  'function getPriceThreshold() view returns (uint256)',
  'function priceThreshold() view returns (uint256)',
  'function isOracleEnabled() view returns (bool)',
  'function isEnabled() view returns (bool)',
  'function enabled() view returns (bool)',
  'function latestAnswer() view returns (int256)',
  'function latestRoundData() view returns (uint80,int256,uint256,uint256,uint80)',
  'function decimals() view returns (uint8)',
  'function description() view returns (string)',
];

const ROLE_NAMES = [
  'DEFAULT_ADMIN_ROLE',
  'UPGRADER_ROLE',
  'REGISTER_ROLE',
  'SPLITTER_ROLE',
  'YIELD_DISTRIBUTION_ROLE',
  'MINTER_ROLE',
  'PAUSE_ROLE',
  'BRIDGE_ROLE',
  'LIST_MANAGER_ROLE',
];
const ROLE_IDS = Object.fromEntries(ROLE_NAMES.map((name) => [name, name === 'DEFAULT_ADMIN_ROLE' ? '0x' + '00'.repeat(32) : id(name)]));
const ROLE_GRANTED = id('RoleGranted(bytes32,address,address)');
const ROLE_REVOKED = id('RoleRevoked(bytes32,address,address)');

function normalize(value) {
  if (value === undefined) return undefined;
  if (value === null) return null;
  if (typeof value === 'bigint') return value.toString();
  if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') return value;
  if (Array.isArray(value)) return value.map(normalize);
  if (value && typeof value === 'object') {
    const out = {};
    for (const [key, item] of Object.entries(value)) {
      if (!/^\d+$/.test(key)) out[key] = normalize(item);
    }
    return out;
  }
  return String(value);
}

function writeJson(name, data) {
  fs.writeFileSync(path.join(OUT, name), JSON.stringify(normalize(data), null, 2) + '\n');
}

function storageWordToAddress(word) {
  if (!word || /^0x0*$/.test(word)) return ZeroAddress;
  return getAddress('0x' + word.slice(-40));
}

async function connect(chain) {
  const attempts = [];
  for (const endpoint of RPCS[chain]) {
    try {
      const provider = new JsonRpcProvider(endpoint, undefined, { staticNetwork: true });
      const [network, block] = await Promise.all([provider.getNetwork(), provider.getBlockNumber()]);
      if (network.chainId !== EXPECTED_CHAIN_IDS[chain]) throw new Error(`wrong chain id ${network.chainId}`);
      attempts.push({ endpoint, ok: true, chainId: network.chainId, block });
      return { provider, endpoint, block, attempts };
    } catch (error) {
      attempts.push({ endpoint, ok: false, error: `${error.name}: ${error.message}` });
    }
  }
  throw new Error(`no ${chain} RPC worked: ${JSON.stringify(attempts)}`);
}

async function tryCall(contract, method, args = []) {
  try {
    const result = await contract[method](...args);
    return { ok: true, value: normalize(result) };
  } catch (error) {
    return { ok: false, error: `${error.shortMessage ?? error.name}: ${error.reason ?? error.message}` };
  }
}

async function fetchProxyState(provider, target) {
  const address = getAddress(target.address);
  const [code, implementationWord, adminWordCanonical, beaconWord] = await Promise.all([
    provider.getCode(address),
    provider.getStorage(address, IMPLEMENTATION_SLOT),
    provider.getStorage(address, ADMIN_SLOT_CANONICAL),
    provider.getStorage(address, BEACON_SLOT),
  ]);
  const implementation = storageWordToAddress(implementationWord);
  const admin = storageWordToAddress(adminWordCanonical);
  const beacon = storageWordToAddress(beaconWord);
  const implementationCode = implementation === ZeroAddress ? '0x' : await provider.getCode(implementation);
  const iface = target.label === 'Register_ETH' ? REGISTRY_ABI : COMMON_ABI;
  const contract = new Contract(address, iface, provider);
  const methods = ['version', 'trustedForwarder', 'fetchRegistry', 'fetchAssetID', 'assetID', 'registry', 'totalSupply', 'previousDistribution', 'paused', 'nftCtr', 'name', 'symbol', 'decimals', 'fetchVaultData'];
  const calls = {};
  for (const method of methods) calls[method] = await tryCall(contract, method);
  return {
    ...target,
    address,
    proxyCodeBytes: Math.max(0, (code.length - 2) / 2),
    proxyCodeHash: keccak256(code),
    implementation,
    implementationCodeBytes: implementationCode === '0x' ? 0 : (implementationCode.length - 2) / 2,
    implementationCodeHash: implementationCode === '0x' ? null : keccak256(implementationCode),
    admin,
    beacon,
    calls,
  };
}

async function scanRoleLogs(provider, address, fromBlock, toBlock) {
  const logs = [];
  let start = fromBlock;
  let chunk = 250_000;
  while (start <= toBlock) {
    const end = Math.min(toBlock, start + chunk - 1);
    try {
      const part = await provider.getLogs({ address, fromBlock: start, toBlock: end, topics: [[ROLE_GRANTED, ROLE_REVOKED]] });
      logs.push(...part);
      start = end + 1;
      if (chunk < 500_000) chunk *= 2;
    } catch (error) {
      if (chunk <= 2_000) throw error;
      chunk = Math.max(2_000, Math.floor(chunk / 2));
    }
  }
  logs.sort((a, b) => a.blockNumber - b.blockNumber || a.index - b.index);
  const state = new Map();
  const decoded = [];
  for (const log of logs) {
    const role = log.topics[1];
    const account = getAddress('0x' + log.topics[2].slice(-40));
    const sender = getAddress('0x' + log.topics[3].slice(-40));
    const granted = log.topics[0].toLowerCase() === ROLE_GRANTED.toLowerCase();
    state.set(`${role.toLowerCase()}:${account.toLowerCase()}`, granted);
    decoded.push({ blockNumber: log.blockNumber, transactionHash: log.transactionHash, logIndex: log.index, granted, role, account, sender });
  }
  const current = [];
  for (const [key, enabled] of state) {
    if (!enabled) continue;
    const [role, accountLower] = key.split(':');
    const source = decoded.findLast((row) => row.role.toLowerCase() === role && row.account.toLowerCase() === accountLower && row.granted);
    current.push({ role, roleName: Object.entries(ROLE_IDS).find(([, value]) => value.toLowerCase() === role)?.[0] ?? null, account: getAddress(accountLower), lastGrantBlock: source?.blockNumber ?? null });
  }
  current.sort((a, b) => (a.roleName ?? a.role).localeCompare(b.roleName ?? b.role) || a.account.localeCompare(b.account));
  return { decoded, current };
}

async function inspectRoleHolders(provider, rows) {
  const unique = [...new Set(rows.map((row) => row.account))];
  const out = [];
  for (const account of unique) {
    const code = await provider.getCode(account);
    out.push({ account, isContract: code !== '0x', codeBytes: code === '0x' ? 0 : (code.length - 2) / 2, codeHash: code === '0x' ? null : keccak256(code) });
  }
  return out;
}

async function main() {
  const chainContexts = {};
  for (const chain of Object.keys(RPCS)) chainContexts[chain] = await connect(chain);
  writeJson('RPC_ATTEMPTS.json', Object.fromEntries(Object.entries(chainContexts).map(([chain, ctx]) => [chain, ctx.attempts])));

  const targetRows = [];
  for (const target of TARGETS) targetRows.push(await fetchProxyState(chainContexts[target.chain].provider, target));
  writeJson('TARGET_STATE.json', targetRows);

  const registerTarget = targetRows.find((row) => row.label === 'Register_ETH');
  const ethProvider = chainContexts.ethereum.provider;
  const registry = new Contract(registerTarget.address, REGISTRY_ABI, ethProvider);
  const registrySummary = {
    counter: await tryCall(registry, 'fetchCounter'),
    usst: await tryCall(registry, 'fetchUSSTToken'),
    yld: await tryCall(registry, 'fetchYLDToken'),
    core: await tryCall(registry, 'fetchCore'),
    treasury: await tryCall(registry, 'fetchTreasury'),
    trustedForwarder: await tryCall(registry, 'trustedForwarder'),
  };
  const counter = registrySummary.counter.ok ? Number(registrySummary.counter.value) : 0;
  const assets = [];
  for (let assetId = 1; assetId <= counter; assetId++) {
    const [definition, deposits] = await Promise.all([
      tryCall(registry, 'fetchAssetData', [assetId]),
      tryCall(registry, 'fetchDeposits', [assetId]),
    ]);
    const row = { assetId, definition, deposits };
    if (definition.ok) {
      const d = definition.value;
      const token = new Contract(d.token, COMMON_ABI, ethProvider);
      const oracle = new Contract(d.oracle, ORACLE_ABI, ethProvider);
      row.token = {
        address: d.token,
        codeHash: keccak256(await ethProvider.getCode(d.token)),
        name: await tryCall(token, 'name'),
        symbol: await tryCall(token, 'symbol'),
        decimals: await tryCall(token, 'decimals'),
        vaultBalance: await tryCall(token, 'balanceOf', [d.vault]),
        distributorBalance: await tryCall(token, 'balanceOf', [d.rewardDistributor]),
      };
      row.oracle = { address: d.oracle, codeHash: keccak256(await ethProvider.getCode(d.oracle)) };
      for (const method of ['fetchPrice', 'fetchPriceDecimals', 'getPriceDecimals', 'priceDecimals', 'fetchPriceThreshold', 'getPriceThreshold', 'priceThreshold', 'isOracleEnabled', 'isEnabled', 'enabled', 'latestAnswer', 'latestRoundData', 'decimals', 'description']) {
        row.oracle[method] = await tryCall(oracle, method);
      }
    }
    assets.push(row);
  }
  writeJson('REGISTRY_AND_ASSETS.json', { registrySummary, assets });

  const roleContracts = [
    { chain: 'ethereum', label: 'Register_ETH', address: '0xa58b634c10df2665a3de1680675d5bb9065847d2', fromBlock: 22_000_000 },
    { chain: 'ethereum', label: 'USST_ETH', address: '0xf9d82660828d8f5d121b14a9dc9c677d91f60065', fromBlock: 22_000_000 },
    { chain: 'ethereum', label: 'YLD_ETH', address: '0xd33c37a90155be8fcab769e38a563e74bfd70e0b', fromBlock: 22_000_000 },
    { chain: 'ethereum', label: 'STBL_Token_ETH', address: '0xb3116013c55d49f575ace3cb0d123f3dbf6cac35', fromBlock: 22_000_000 },
    { chain: 'bsc', label: 'USST_BSC', address: '0x1171ce10262a60c17507580a3b70b956f20a35de', fromBlock: 40_000_000 },
    { chain: 'bsc', label: 'STBL_Token_BSC', address: '0x8dedf84656fa932157e27c060d8613824e7979e3', fromBlock: 40_000_000 },
  ];
  const roleOutput = [];
  for (const item of roleContracts) {
    const ctx = chainContexts[item.chain];
    const scan = await scanRoleLogs(ctx.provider, getAddress(item.address), item.fromBlock, ctx.block);
    const holders = await inspectRoleHolders(ctx.provider, scan.current);
    roleOutput.push({ ...item, toBlock: ctx.block, currentRoles: scan.current, holders, eventCount: scan.decoded.length, events: scan.decoded });
  }
  writeJson('ROLE_TOPOLOGY.json', roleOutput);

  const forwarderAddress = registrySummary.trustedForwarder.ok ? registrySummary.trustedForwarder.value : ZeroAddress;
  let forwarder = null;
  if (forwarderAddress && forwarderAddress !== ZeroAddress) {
    const code = await ethProvider.getCode(forwarderAddress);
    forwarder = { address: forwarderAddress, codeBytes: code === '0x' ? 0 : (code.length - 2) / 2, codeHash: code === '0x' ? null : keccak256(code) };
  }
  writeJson('TRUSTED_FORWARDER.json', forwarder);

  const summary = {
    status: 'PASS_STBL_READ_ONLY_STATE_MAP',
    checkedBlocks: Object.fromEntries(Object.entries(chainContexts).map(([chain, ctx]) => [chain, ctx.block])),
    targets: targetRows.length,
    registryAssetCount: counter,
    currentRoleAssignments: roleOutput.reduce((sum, row) => sum + row.currentRoles.length, 0),
    trustedForwarder: forwarder,
    publicChainTransactions: 0,
  };
  writeJson('SUMMARY.json', summary);
  const manifest = fs.readdirSync(OUT).sort().map((name) => {
    const data = fs.readFileSync(path.join(OUT, name));
    return { name, bytes: data.length, sha256: keccak256(data) };
  });
  writeJson('MANIFEST.json', manifest);
  console.log(JSON.stringify(summary, null, 2));
}

main().catch((error) => {
  fs.writeFileSync(path.join(OUT, 'ERROR.txt'), `${error.stack ?? error}\n`);
  console.error(error.stack ?? error);
  process.exit(1);
});
