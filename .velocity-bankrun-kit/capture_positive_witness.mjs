import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import bs58 from 'bs58';
import { Connection, Keypair, PublicKey } from '@solana/web3.js';
import * as sdk from '@velocity-exchange/sdk';

const OUT = path.resolve(process.env.OUT_DIR ?? 'snapshot');
const PROGRAM = new PublicKey('vELoC1audYbSYVRXn1vPaV8Axoa9oU6BYmNGZZBDZ1P');
const PYTH_STORAGE = new PublicKey('3rdJbqfnagQ4yx9HXJViD4zc4xpiSqmFsKpPuSCQVyQL');
const CANDIDATE_SIGNATURE = 'sD3g31zyumf4As1JP5LQ9ABPCsNESt9tcvhJYZGwEUbXzhR77yk2MYhnfcZDqTtGv6ypZJftaqeDTvDV8i8v6dK';
const EXPECTED_MESSAGE_SHA256 = 'b9e28e0d937332a1a9f2d1cdd430b1b4a7081323cc00f0a7b3c4eda39c372c72';
const EXPECTED_ACTIVE_ELF = '1b7b06d17af813b5a505df8f534bfd0779a1a7457f0d2626b1a45c8741686c80';
const RPCS = [
  'https://solana-rpc.publicnode.com',
  'https://api.mainnet-beta.solana.com',
  'https://solana.drpc.org',
  'https://1rpc.io/solana',
  'https://mainnet-beta.solflare.network',
  'https://solana-mainnet.rpc.extrnode.com',
];

fs.mkdirSync(OUT, { recursive: true });
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const sha256 = (data) => crypto.createHash('sha256').update(data).digest('hex');

function normalize(value, seen = new WeakSet()) {
  if (value === undefined) return undefined;
  if (value === null) return null;
  if (typeof value === 'bigint') return value.toString();
  if (['number', 'string', 'boolean'].includes(typeof value)) return value;
  if (Buffer.isBuffer(value) || value instanceof Uint8Array) return { bytes: value.length, base64: Buffer.from(value).toString('base64') };
  if (value?.toBase58) return value.toBase58();
  if (value?.constructor?.name === 'BN' && value?.toString) return value.toString();
  if (Array.isArray(value)) return value.map((item) => normalize(item, seen));
  if (typeof value === 'object') {
    if (seen.has(value)) return '[Circular]';
    seen.add(value);
    const out = {};
    for (const [key, child] of Object.entries(value)) {
      const nv = normalize(child, seen);
      if (nv !== undefined) out[key] = nv;
    }
    seen.delete(value);
    return out;
  }
  return String(value);
}

function writeJson(name, value) {
  fs.writeFileSync(path.join(OUT, name), JSON.stringify(normalize(value), null, 2) + '\n');
}

async function rawRpc(endpoint, method, params, timeoutMs = 120_000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(endpoint, {
      method: 'POST',
      headers: { 'content-type': 'application/json', accept: 'application/json', 'user-agent': 'Velocity-Public-Witness-Snapshot/1.0' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
      signal: controller.signal,
    });
    const text = await response.text();
    if (!response.ok) throw new Error(`HTTP ${response.status}: ${text.slice(0, 300)}`);
    const body = JSON.parse(text);
    if (body.error) throw new Error(JSON.stringify(body.error));
    return body.result;
  } finally {
    clearTimeout(timer);
  }
}

let cursor = 0;
async function rpc(method, params, attempts = 18, timeoutMs = 120_000) {
  let lastError;
  for (let attempt = 0; attempt < attempts; attempt++) {
    const endpoint = RPCS[(cursor + attempt) % RPCS.length];
    try {
      const result = await rawRpc(endpoint, method, params, timeoutMs);
      cursor = (RPCS.indexOf(endpoint) + 1) % RPCS.length;
      return { endpoint, result };
    } catch (error) {
      lastError = error;
      await sleep(Math.min(5000, 100 * 2 ** Math.min(attempt, 5)));
    }
  }
  throw lastError;
}

function canonicalElfSize(data) {
  if (data.length < 64 || data.subarray(0, 4).toString('hex') !== '7f454c46' || data[4] !== 2 || data[5] !== 1) throw new Error('invalid ELF payload');
  const phoff = Number(data.readBigUInt64LE(0x20));
  const shoff = Number(data.readBigUInt64LE(0x28));
  const ehsize = data.readUInt16LE(0x34);
  const phentsize = data.readUInt16LE(0x36);
  const phnum = data.readUInt16LE(0x38);
  const shentsize = data.readUInt16LE(0x3a);
  const shnum = data.readUInt16LE(0x3c);
  let maximum = Math.max(64, ehsize);
  if (phoff && phentsize && phnum) {
    maximum = Math.max(maximum, phoff + phentsize * phnum);
    for (let i = 0; i < phnum; i++) {
      const offset = phoff + i * phentsize;
      maximum = Math.max(maximum, Number(data.readBigUInt64LE(offset + 8) + data.readBigUInt64LE(offset + 32)));
    }
  }
  if (shoff && shentsize && shnum) {
    maximum = Math.max(maximum, shoff + shentsize * shnum);
    for (let i = 0; i < shnum; i++) {
      const offset = shoff + i * shentsize;
      if (data.readUInt32LE(offset + 4) !== 8) maximum = Math.max(maximum, Number(data.readBigUInt64LE(offset + 24) + data.readBigUInt64LE(offset + 32)));
    }
  }
  return maximum;
}

function combinedAccountKeys(tx) {
  const message = tx.transaction.message;
  const staticKeys = (message.accountKeys ?? message.staticAccountKeys ?? []).map((value) =>
    typeof value === 'string' ? value : value?.pubkey ? String(value.pubkey) : String(value)
  );
  const loaded = tx.meta?.loadedAddresses ?? { writable: [], readonly: [] };
  return [...staticKeys, ...(loaded.writable ?? []).map(String), ...(loaded.readonly ?? []).map(String)];
}

function decodeAccount(coder, names, raw) {
  const errors = [];
  for (const name of names) {
    try { return coder.accounts.decode(name, raw); } catch (error) { errors.push(`${name}: ${error}`); }
  }
  throw new Error(errors.join(' | '));
}

async function main() {
  sdk.initialize({ env: 'mainnet-beta' });
  const programResponse = await rpc('getAccountInfo', [PROGRAM.toBase58(), { encoding: 'base64', commitment: 'finalized' }]);
  const programValue = programResponse.result?.value;
  if (!programValue?.executable) throw new Error('Velocity program missing/non-executable');
  const programRaw = Buffer.from(programValue.data[0], 'base64');
  const programData = new PublicKey(programRaw.subarray(4, 36));
  const pd = await rpc('getAccountInfo', [programData.toBase58(), { encoding: 'base64', commitment: 'finalized' }], 18, 240_000);
  const pdRaw = Buffer.from(pd.result.value.data[0], 'base64');
  const payload = pdRaw.subarray(45);
  const activeElf = payload.subarray(0, canonicalElfSize(payload));
  if (sha256(activeElf) !== EXPECTED_ACTIVE_ELF) throw new Error(`active ELF changed: ${sha256(activeElf)}`);
  fs.writeFileSync(path.join(OUT, 'VELOCITY_ACTIVE_PROGRAM_CANONICAL.so'), activeElf);

  const connection = new Connection(programResponse.endpoint, 'finalized');
  const decoder = new sdk.VelocityClient({
    connection,
    wallet: new sdk.Wallet(Keypair.generate()),
    programID: PROGRAM,
    env: 'mainnet-beta',
    opts: { commitment: 'finalized', preflightCommitment: 'finalized' },
    activeSubAccountId: 0,
    subAccountIds: [],
    perpMarketIndexes: [],
    spotMarketIndexes: [],
    oracleInfos: [],
    accountSubscription: { type: 'websocket' },
    userStats: false,
    skipLoadUsers: true,
    txVersion: 'legacy',
    marketLookupTables: [],
  });

  const statePda = await sdk.getVelocityStateAccountPublicKey(PROGRAM);
  const spot0Pda = await sdk.getSpotMarketPublicKey(PROGRAM, 0);
  const spot1Pda = await sdk.getSpotMarketPublicKey(PROGRAM, 1);
  const perp0Pda = await sdk.getPerpMarketPublicKey(PROGRAM, 0);
  const primaryKeys = [statePda, spot0Pda, spot1Pda, perp0Pda, PYTH_STORAGE];
  const primary = await rpc('getMultipleAccounts', [primaryKeys.map(String), { encoding: 'base64', commitment: 'finalized' }]);
  if (primary.result.value.some((value) => !value)) throw new Error('primary account missing');
  const spot0 = decodeAccount(decoder.program.coder, ['spotMarket', 'SpotMarket'], Buffer.from(primary.result.value[1].data[0], 'base64'));
  const spot1 = decodeAccount(decoder.program.coder, ['spotMarket', 'SpotMarket'], Buffer.from(primary.result.value[2].data[0], 'base64'));
  const perp0 = decodeAccount(decoder.program.coder, ['perpMarket', 'PerpMarket'], Buffer.from(primary.result.value[3].data[0], 'base64'));

  const candidateResponse = await rpc('getTransaction', [CANDIDATE_SIGNATURE, { encoding: 'json', commitment: 'finalized', maxSupportedTransactionVersion: 0 }], 18, 180_000);
  const tx = candidateResponse.result;
  if (!tx) throw new Error('candidate transaction missing');
  const keys = combinedAccountKeys(tx);
  const instructions = tx.transaction.message.instructions ?? tx.transaction.message.compiledInstructions ?? [];
  let candidateInstruction = null;
  for (let index = 0; index < instructions.length; index++) {
    const ix = instructions[index];
    const programId = String(ix.programId ?? keys[ix.programIdIndex]);
    if (programId !== PROGRAM.toBase58()) continue;
    const data = Buffer.from(bs58.decode(ix.data));
    if (data.length < 114) continue;
    for (let offset = 0; offset <= Math.min(32, data.length - 114); offset++) {
      if (data.readUInt32LE(offset) !== 2182742457) continue;
      const message = data.subarray(offset);
      if (sha256(message) === EXPECTED_MESSAGE_SHA256) {
        candidateInstruction = {
          index,
          dataBase58: ix.data,
          dataBase64: data.toString('base64'),
          dataBytes: data.length,
          messageOffset: offset,
          messageSha256: sha256(message),
          messageHex: message.toString('hex'),
          accountIndexes: ix.accounts ?? ix.accountKeyIndexes ?? [],
          accountKeys: (ix.accounts ?? ix.accountKeyIndexes ?? []).map((accountIndex) => keys[accountIndex]),
        };
      }
    }
  }
  if (!candidateInstruction) throw new Error('exact candidate Velocity update instruction not found');

  const dynamicKeys = [
    spot0.mint, spot0.vault, spot0.oracle,
    spot1.mint, spot1.vault, spot1.oracle,
    perp0.oracle,
    ...candidateInstruction.accountKeys,
  ].map(String);
  const allKeys = [...new Set([...primaryKeys.map(String), ...dynamicKeys])];
  const accounts = [];
  for (let start = 0; start < allKeys.length; start += 100) {
    const chunk = allKeys.slice(start, start + 100);
    const response = await rpc('getMultipleAccounts', [chunk, { encoding: 'base64', commitment: 'finalized' }]);
    response.result.value.forEach((value, index) => {
      if (!value) throw new Error(`required account missing: ${chunk[index]}`);
      accounts.push({
        address: chunk[index],
        executable: value.executable,
        lamports: value.lamports,
        owner: value.owner,
        rentEpoch: value.rentEpoch ?? 0,
        dataBase64: value.data[0],
        dataBytes: Buffer.from(value.data[0], 'base64').length,
        dataSha256: sha256(Buffer.from(value.data[0], 'base64')),
        provenance: 'current_finalized_read_only_rpc',
      });
    });
  }

  const result = {
    status: 'PASS_PUBLIC_POSITIVE_WITNESS_DEPENDENCY_SNAPSHOT',
    programId: PROGRAM,
    programData,
    activeElfSha256: sha256(activeElf),
    statePda,
    spot0Pda,
    spot1Pda,
    perp0Pda,
    pythStorage: PYTH_STORAGE,
    decoded: { spot0, spot1, perp0 },
    candidate: {
      signature: CANDIDATE_SIGNATURE,
      slot: tx.slot,
      blockTime: tx.blockTime,
      expectedMessageSha256: EXPECTED_MESSAGE_SHA256,
      instruction: candidateInstruction,
    },
    accounts,
    safety: {
      publicChainTransactionsSigned: 0,
      publicChainTransactionsSent: 0,
      publicChainWrites: 0,
      rpcMethods: ['getAccountInfo', 'getMultipleAccounts', 'getTransaction'],
    },
  };
  writeJson('snapshot.json', result);
  console.log(`STATUS=${result.status}`);
  console.log(`ACCOUNTS=${accounts.length}`);
  console.log(`CANDIDATE_SLOT=${tx.slot}`);
  console.log(`ACTIVE_ELF_SHA256=${result.activeElfSha256}`);
  console.log('PUBLIC_CHAIN_TRANSACTIONS=0');
}

main().catch((error) => {
  writeJson('failure.json', { status: 'FAILED', error: String(error?.stack ?? error), safety: { publicChainWrites: 0 } });
  console.error(error?.stack ?? error);
  process.exit(1);
});
