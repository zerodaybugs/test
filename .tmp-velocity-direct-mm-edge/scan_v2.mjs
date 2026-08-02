import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import bs58 from 'bs58';
import { Connection, Keypair, PublicKey } from '@solana/web3.js';
import * as sdk from '@velocity-exchange/sdk';

const OUT = path.resolve(process.env.OUT_DIR ?? 'evidence');
const PROGRAM = new PublicKey('vELoC1audYbSYVRXn1vPaV8Axoa9oU6BYmNGZZBDZ1P');
const EXPECTED_ACTIVE_ELF = '1b7b06d17af813b5a505df8f534bfd0779a1a7457f0d2626b1a45c8741686c80';
const FEEDS = [
  { marketIndex: 0, feedId: 6, symbol: 'SOL-PERP' },
  { marketIndex: 1, feedId: 1, symbol: 'BTC-PERP' },
  { marketIndex: 2, feedId: 2, symbol: 'ETH-PERP' },
  { marketIndex: 3, feedId: 110, symbol: 'HYPE-PERP' },
];
const RPCS = [
  'https://solana-rpc.publicnode.com',
  'https://api.mainnet-beta.solana.com',
  'https://solana.drpc.org',
  'https://1rpc.io/solana',
  'https://mainnet-beta.solflare.network',
  'https://solana-mainnet.rpc.extrnode.com',
];
const ATTEMPTS = Math.max(100, Math.min(10000, Number(process.env.ATTEMPTS ?? 6000)));
const SLEEP_MS = Math.max(100, Math.min(2000, Number(process.env.SLEEP_MS ?? 200)));
const MIN_NET_EDGE_BPS = Number(process.env.MIN_NET_EDGE_BPS ?? 0.5);
const EXECUTION_BUFFER_BPS = Number(process.env.EXECUTION_BUFFER_BPS ?? 0.75);
const MAX_PROJECTED_WAIT_SLOTS = BigInt(Math.max(1, Math.min(12, Number(process.env.MAX_PROJECTED_WAIT_SLOTS ?? 6))));
const CONSERVATIVE_SLOT_SECONDS = Number(process.env.CONSERVATIVE_SLOT_SECONDS ?? 0.6);

fs.mkdirSync(OUT, { recursive: true });
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const sha256 = (data) => crypto.createHash('sha256').update(data).digest('hex');
const bn = (value) => BigInt(value.toString());

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

async function rawRpc(endpoint, method, params, timeoutMs = 60_000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(endpoint, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        accept: 'application/json',
        'user-agent': 'Velocity-Public-Projected-Oracle-Edge-Census/2.0',
      },
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

let rpcCursor = 0;
async function rpc(method, params, attempts = 14, timeoutMs = 60_000) {
  let lastError;
  for (let attempt = 0; attempt < attempts; attempt++) {
    const endpoint = RPCS[(rpcCursor + attempt) % RPCS.length];
    try {
      const result = await rawRpc(endpoint, method, params, timeoutMs);
      rpcCursor = (RPCS.indexOf(endpoint) + 1) % RPCS.length;
      return { endpoint, result };
    } catch (error) {
      lastError = error;
      await sleep(Math.min(4000, 100 * 2 ** Math.min(attempt, 5)));
    }
  }
  throw lastError;
}

function canonicalElfSize(data) {
  if (data.length < 64 || data.subarray(0, 4).toString('hex') !== '7f454c46' || data[4] !== 2 || data[5] !== 1) throw new Error('ProgramData payload is not ELF64 little-endian');
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
  if (maximum > data.length) throw new Error('ELF extent exceeds payload');
  return maximum;
}

function decodeOracle(raw) {
  if (raw.length < 48) throw new Error(`oracle account too short: ${raw.length}`);
  return {
    price: raw.readBigInt64LE(8),
    publishTime: raw.readBigUInt64LE(16),
    postedSlot: raw.readBigUInt64LE(24),
    exponent: raw.readInt32LE(32),
    conf: raw.readBigUInt64LE(40),
  };
}

function toPricePrecision(price, exponent) {
  const shift = BigInt(exponent + 6);
  return shift >= 0n ? price * (10n ** shift) : price / (10n ** (-shift));
}

function reservePrice(amm, side) {
  const base = side === 'bid' ? bn(amm.bidBaseAssetReserve) : bn(amm.askBaseAssetReserve);
  const quote = side === 'bid' ? bn(amm.bidQuoteAssetReserve) : bn(amm.askQuoteAssetReserve);
  if (base <= 0n) throw new Error('non-positive AMM base reserve');
  return quote * bn(amm.pegMultiplier) / base;
}

function decodeAccount(coder, names, raw) {
  const errors = [];
  for (const name of names) {
    try { return coder.accounts.decode(name, raw); } catch (error) { errors.push(`${name}: ${error}`); }
  }
  throw new Error(errors.join(' | '));
}

function combinedAccountKeys(tx) {
  const message = tx.transaction.message;
  const staticKeys = (message.accountKeys ?? message.staticAccountKeys ?? []).map((value) =>
    typeof value === 'string' ? value : value?.pubkey ? String(value.pubkey) : String(value)
  );
  const loaded = tx.meta?.loadedAddresses ?? { writable: [], readonly: [] };
  return [...staticKeys, ...(loaded.writable ?? []).map(String), ...(loaded.readonly ?? []).map(String)];
}

function decodePythLazerMessage(message) {
  if (message.length < 114 || message.readUInt32LE(0) !== 2182742457) throw new Error('not Pyth Lazer Solana message');
  const payloadLength = message.readUInt16LE(100);
  const payload = message.subarray(102, 102 + payloadLength);
  if (payload.length !== payloadLength || payload.readUInt32LE(0) !== 2479346549) throw new Error('bad payload');
  let offset = 4;
  const payloadTimestampUs = payload.readBigUInt64LE(offset); offset += 8;
  const channelId = payload.readUInt8(offset); offset += 1;
  const feedCount = payload.readUInt8(offset); offset += 1;
  const feeds = [];
  const optionalI64 = () => { const v = payload.readBigInt64LE(offset); offset += 8; return v === 0n ? null : v; };
  const optionalU64 = () => { const present = payload.readUInt8(offset); offset += 1; if (!present) return null; const v = payload.readBigUInt64LE(offset); offset += 8; return v; };
  for (let feedIndex = 0; feedIndex < feedCount; feedIndex++) {
    const feedId = payload.readUInt32LE(offset); offset += 4;
    const propertyCount = payload.readUInt8(offset); offset += 1;
    const properties = {};
    const propertyIds = [];
    for (let propertyIndex = 0; propertyIndex < propertyCount; propertyIndex++) {
      const property = payload.readUInt8(offset); offset += 1;
      propertyIds.push(property);
      switch (property) {
        case 0: properties.price = optionalI64(); break;
        case 1: properties.bestBidPrice = optionalI64(); break;
        case 2: properties.bestAskPrice = optionalI64(); break;
        case 3: properties.publisherCount = payload.readUInt16LE(offset); offset += 2; break;
        case 4: properties.exponent = payload.readInt16LE(offset); offset += 2; break;
        case 5: properties.confidence = optionalI64(); break;
        case 6: { const present = payload.readUInt8(offset); offset += 1; properties.fundingRate = present ? payload.readBigInt64LE(offset) : null; if (present) offset += 8; break; }
        case 7: properties.fundingTimestamp = optionalU64(); break;
        case 8: properties.fundingRateInterval = optionalU64(); break;
        case 9: properties.marketSession = payload.readInt16LE(offset); offset += 2; break;
        case 10: properties.emaPrice = optionalI64(); break;
        case 11: properties.emaConfidence = optionalI64(); break;
        case 12: properties.feedUpdateTimestamp = optionalU64(); break;
        default: throw new Error(`unsupported property ${property}`);
      }
    }
    feeds.push({ feedId, propertyIds, properties });
  }
  if (offset !== payload.length) throw new Error('payload trailing bytes');
  return { payloadTimestampUs, channelId, feeds };
}

function findExactUpdate(tx, oracleAddress, expected) {
  const keys = combinedAccountKeys(tx);
  const instructions = tx.transaction.message.instructions ?? tx.transaction.message.compiledInstructions ?? [];
  for (let index = 0; index < instructions.length; index++) {
    const instruction = instructions[index];
    const programId = instruction.programId ?? keys[instruction.programIdIndex];
    if (String(programId) !== PROGRAM.toBase58()) continue;
    const data = Buffer.from(bs58.decode(instruction.data));
    if (data.length < 114) continue;
    for (let offset = 0; offset <= Math.min(32, data.length - 114); offset++) {
      if (data.readUInt32LE(offset) !== 2182742457) continue;
      try {
        const signedMessage = data.subarray(offset);
        const decoded = decodePythLazerMessage(signedMessage);
        const feed = decoded.feeds.find((item) => item.feedId === expected.feedId);
        const accounts = (instruction.accounts ?? instruction.accountKeyIndexes ?? []).map((i) => keys[i]);
        if (feed && accounts.includes(oracleAddress) && feed.properties.price === expected.rawPrice && feed.properties.exponent === expected.exponent && feed.properties.feedUpdateTimestamp === expected.publishTime) {
          return {
            instructionIndex: index,
            dataOffset: offset,
            signedMessageHex: signedMessage.toString('hex'),
            signedMessageSha256: sha256(signedMessage),
            channelId: decoded.channelId,
            payloadTimestampUs: decoded.payloadTimestampUs,
            feed,
          };
        }
      } catch {}
    }
  }
  return null;
}

async function recoverExactPayload(endpoint, oracleAddress, postedSlot, expected) {
  const rows = (await rawRpc(endpoint, 'getSignaturesForAddress', [oracleAddress, { limit: 100, commitment: 'finalized' }], 90_000)) ?? [];
  for (const row of rows.filter((item) => Number(item.slot) === Number(postedSlot))) {
    const tx = await rawRpc(endpoint, 'getTransaction', [row.signature, { encoding: 'json', commitment: 'finalized', maxSupportedTransactionVersion: 0 }], 90_000);
    if (!tx) continue;
    const exact = findExactUpdate(tx, oracleAddress, expected);
    if (exact) return { signature: row.signature, slot: row.slot, blockTime: tx.blockTime, ...exact };
  }
  return null;
}

function slotsUntilStale(delay, threshold) {
  const requiredDelay = threshold + 1n;
  return delay >= requiredDelay ? 0n : requiredDelay - delay;
}

async function main() {
  sdk.initialize({ env: 'mainnet-beta' });
  const probe = await rpc('getAccountInfo', [PROGRAM.toBase58(), { encoding: 'base64', commitment: 'finalized' }]);
  if (!probe.result?.value?.executable) throw new Error('Velocity program account missing/non-executable');
  const programRaw = Buffer.from(probe.result.value.data[0], 'base64');
  const programData = new PublicKey(programRaw.subarray(4, 36));
  const pd = await rpc('getAccountInfo', [programData.toBase58(), { encoding: 'base64', commitment: 'finalized' }], 14, 180_000);
  const pdRaw = Buffer.from(pd.result.value.data[0], 'base64');
  const canonical = pdRaw.subarray(45, 45 + canonicalElfSize(pdRaw.subarray(45)));
  const activeElfSha256 = sha256(canonical);
  if (activeElfSha256 !== EXPECTED_ACTIVE_ELF) throw new Error(`active ELF changed: ${activeElfSha256}`);

  const connection = new Connection(probe.endpoint, 'finalized');
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
  const perpPdas = await Promise.all(FEEDS.map(({ marketIndex }) => sdk.getPerpMarketPublicKey(PROGRAM, marketIndex)));
  const initial = await rpc('getMultipleAccounts', [[statePda.toBase58(), ...perpPdas.map(String)], { encoding: 'base64', commitment: 'finalized' }]);
  if (initial.result.value.some((value) => !value)) throw new Error('state/perp account missing');
  const stateRaw = Buffer.from(initial.result.value[0].data[0], 'base64');
  const state = decodeAccount(decoder.program.coder, ['state', 'State'], stateRaw);
  const initialMarkets = initial.result.value.slice(1).map((value) => decodeAccount(decoder.program.coder, ['perpMarket', 'PerpMarket'], Buffer.from(value.data[0], 'base64')));
  const oracleAddresses = initialMarkets.map((market) => market.oracle.toBase58());
  const feeTier = state.perpFeeStructure?.feeTiers?.[0] ?? state.perp_fee_structure?.fee_tiers?.[0];
  const feeNumerator = Number(feeTier?.feeNumerator?.toString?.() ?? feeTier?.fee_numerator?.toString?.() ?? 35);
  const feeDenominator = Number(feeTier?.feeDenominator?.toString?.() ?? feeTier?.fee_denominator?.toString?.() ?? 100000);
  const takerFeeBps = feeNumerator / feeDenominator * 10_000;

  const observations = [];
  const projectedCandidates = [];
  let best = null;
  let bestProjected = null;
  let positiveWitness = null;
  let lastProgress = Date.now();
  let rpcFailures = 0;
  let missingAccountResponses = 0;
  let payloadRecoveryFailures = 0;

  for (let attempt = 0; attempt < ATTEMPTS; attempt++) {
    let response;
    try {
      response = await rpc('getMultipleAccounts', [[...perpPdas.map(String), ...oracleAddresses], { encoding: 'base64', commitment: 'finalized' }], 14, 60_000);
    } catch (error) {
      rpcFailures++;
      if (rpcFailures > Math.max(30, Math.floor(ATTEMPTS * 0.03))) throw error;
      await sleep(SLEEP_MS);
      continue;
    }
    const values = response.result?.value;
    if (!Array.isArray(values) || values.length !== FEEDS.length * 2 || values.some((value) => !value)) {
      missingAccountResponses++;
      await sleep(SLEEP_MS);
      continue;
    }
    const contextSlot = BigInt(response.result.context.slot);
    const markets = values.slice(0, FEEDS.length).map((value) => decodeAccount(decoder.program.coder, ['perpMarket', 'PerpMarket'], Buffer.from(value.data[0], 'base64')));
    const oracles = values.slice(FEEDS.length).map((value) => decodeOracle(Buffer.from(value.data[0], 'base64')));

    for (let i = 0; i < FEEDS.length; i++) {
      const config = FEEDS[i];
      const market = markets[i];
      const oracle = oracles[i];
      const marketRawBase64 = values[i].data[0];
      const oracleRawBase64 = values[FEEDS.length + i].data[0];
      const directPrice = toPricePrecision(oracle.price, oracle.exponent);
      const bidPrice = reservePrice(market.amm, 'bid');
      const askPrice = reservePrice(market.amm, 'ask');
      const longGrossBps = Number(directPrice - askPrice) / Number(directPrice) * 10_000;
      const shortGrossBps = Number(bidPrice - directPrice) / Number(directPrice) * 10_000;
      const direction = longGrossBps >= shortGrossBps ? 'LONG' : 'SHORT';
      const grossEdgeBps = Math.max(longGrossBps, shortGrossBps);
      const netEdgeBps = grossEdgeBps - takerFeeBps - EXECUTION_BUFFER_BPS;
      const mmSequence = bn(market.marketStats.mmOracleSequenceId);
      const mmSlot = bn(market.marketStats.mmOracleSlot);
      const rawOverride = Number(market.amm.oracleSlotDelayOverride ?? 0);
      const immediateThreshold = rawOverride > 0 ? BigInt(rawOverride) : 0n;
      const directDelay = contextSlot > oracle.postedSlot ? contextSlot - oracle.postedSlot : 0n;
      const mmDelay = contextSlot > mmSlot ? contextSlot - mmSlot : 0n;
      const directAhead = oracle.publishTime > mmSequence;
      const directWait = slotsUntilStale(directDelay, immediateThreshold);
      const mmWait = slotsUntilStale(mmDelay, immediateThreshold);
      const slotsUntilControlBlocked = directWait > mmWait ? directWait : mmWait;
      const projectedTriggerSlot = contextSlot + slotsUntilControlBlocked;
      const currentlyBlocked = directWait === 0n && mmWait === 0n;
      const projectable = slotsUntilControlBlocked <= MAX_PROJECTED_WAIT_SLOTS;
      const row = {
        attempt,
        contextSlot,
        projectedTriggerSlot,
        rpc: response.endpoint,
        marketIndex: config.marketIndex,
        marketPda: perpPdas[i],
        feedId: config.feedId,
        symbol: config.symbol,
        oracleAddress: oracleAddresses[i],
        directPrice,
        bidPrice,
        askPrice,
        longGrossBps,
        shortGrossBps,
        direction,
        grossEdgeBps,
        takerFeeBps,
        executionBufferBps: EXECUTION_BUFFER_BPS,
        netEdgeBps,
        oraclePostedSlot: oracle.postedSlot,
        oraclePublishTime: oracle.publishTime,
        directDelay,
        mmOracleSlot: mmSlot,
        mmOracleSequenceId: mmSequence,
        mmDelay,
        directAhead,
        directLeadMicros: oracle.publishTime - mmSequence,
        immediateThreshold,
        slotsUntilControlBlocked,
        currentlyBlocked,
        projectable,
        baseSpread: market.amm.baseSpread,
        longSpread: market.amm.longSpread,
        shortSpread: market.amm.shortSpread,
        maxOpenInterest: market.amm.maxOpenInterest ?? market.maxOpenInterest,
      };
      if (!best || row.netEdgeBps > best.netEdgeBps) best = row;
      if (directAhead) observations.push(row);
      if (directAhead && projectable && netEdgeBps >= MIN_NET_EDGE_BPS) {
        projectedCandidates.push(row);
        if (!bestProjected || row.netEdgeBps > bestProjected.netEdgeBps) bestProjected = row;
        const payload = await recoverExactPayload(response.endpoint, oracleAddresses[i], oracle.postedSlot, {
          feedId: config.feedId,
          rawPrice: oracle.price,
          exponent: oracle.exponent,
          publishTime: oracle.publishTime,
        }).catch(() => null);
        if (!payload) {
          payloadRecoveryFailures++;
          continue;
        }
        const currentBlockTime = await rawRpc(response.endpoint, 'getBlockTime', [Number(contextSlot)], 60_000).catch(() => null);
        const payloadAgeAtObservationSeconds = currentBlockTime == null ? null : Number(BigInt(currentBlockTime) - payload.payloadTimestampUs / 1_000_000n);
        const projectedPayloadAgeSeconds = payloadAgeAtObservationSeconds == null
          ? null
          : payloadAgeAtObservationSeconds + Number(slotsUntilControlBlocked) * CONSERVATIVE_SLOT_SECONDS;
        const messageAgeGateSatisfied = projectedPayloadAgeSeconds == null
          ? null
          : projectedPayloadAgeSeconds >= 0 && projectedPayloadAgeSeconds <= 15;
        const witness = {
          ...row,
          exactPayload: payload,
          currentBlockTime,
          payloadAgeAtObservationSeconds,
          projectedPayloadAgeSeconds,
          messageAgeGateSatisfied,
          rawSnapshot: {
            statePda,
            stateBase64: stateRaw.toString('base64'),
            marketBase64: marketRawBase64,
            oracleBase64: oracleRawBase64,
          },
        };
        if (!positiveWitness || witness.netEdgeBps > positiveWitness.netEdgeBps) positiveWitness = witness;
        if (messageAgeGateSatisfied === true) break;
      }
    }
    if (positiveWitness?.messageAgeGateSatisfied === true) break;
    if (Date.now() - lastProgress > 15_000) {
      console.log(`PROGRESS=${attempt + 1}/${ATTEMPTS} DIRECT_AHEAD=${observations.length} PROJECTED=${projectedCandidates.length} BEST_NET_EDGE_BPS=${best?.netEdgeBps} BEST_PROJECTED_BPS=${bestProjected?.netEdgeBps} MISSING=${missingAccountResponses}`);
      lastProgress = Date.now();
    }
    await sleep(SLEEP_MS);
  }

  observations.sort((a, b) => b.netEdgeBps - a.netEdgeBps);
  projectedCandidates.sort((a, b) => b.netEdgeBps - a.netEdgeBps);
  const result = {
    verdict: positiveWitness?.messageAgeGateSatisfied === true
      ? 'POSITIVE_PROJECTED_REPLAYABLE_EDGE_WITNESS'
      : 'NO_PROJECTED_REPLAYABLE_POSITIVE_EDGE_OBSERVED',
    activeElfSha256,
    programId: PROGRAM,
    programData,
    statePda,
    attemptsConfigured: ATTEMPTS,
    sleepMs: SLEEP_MS,
    minNetEdgeBps: MIN_NET_EDGE_BPS,
    takerFeeBps,
    executionBufferBps: EXECUTION_BUFFER_BPS,
    maxProjectedWaitSlots: MAX_PROJECTED_WAIT_SLOTS,
    conservativeSlotSeconds: CONSERVATIVE_SLOT_SECONDS,
    rpcFailures,
    missingAccountResponses,
    payloadRecoveryFailures,
    directAheadObservationCount: observations.length,
    projectedCandidateCount: projectedCandidates.length,
    bestObservation: observations[0] ?? best,
    bestProjectedCandidate: projectedCandidates[0] ?? bestProjected,
    topObservations: observations.slice(0, 200),
    topProjectedCandidates: projectedCandidates.slice(0, 100),
    positiveWitness,
    safety: {
      publicChainWrites: 0,
      publicTransactionsSigned: 0,
      publicTransactionsSent: 0,
      productionPrivateKeys: 0,
      rpcMethods: ['getAccountInfo', 'getMultipleAccounts', 'getSignaturesForAddress', 'getTransaction', 'getBlockTime'],
    },
  };
  writeJson('RESULT.json', result);
  const files = fs.readdirSync(OUT).sort().map((name) => {
    const data = fs.readFileSync(path.join(OUT, name));
    return { name, bytes: data.length, sha256: sha256(data) };
  });
  writeJson('MANIFEST.json', files);
  console.log(`VERDICT=${result.verdict}`);
  console.log(`DIRECT_AHEAD_OBSERVATIONS=${result.directAheadObservationCount}`);
  console.log(`PROJECTED_CANDIDATES=${result.projectedCandidateCount}`);
  console.log(`BEST_NET_EDGE_BPS=${result.bestObservation?.netEdgeBps}`);
  console.log(`BEST_PROJECTED_NET_EDGE_BPS=${result.bestProjectedCandidate?.netEdgeBps}`);
  console.log(`BEST_PROJECTED_SYMBOL=${result.bestProjectedCandidate?.symbol}`);
  console.log(`BEST_PROJECTED_WAIT_SLOTS=${result.bestProjectedCandidate?.slotsUntilControlBlocked}`);
  console.log('PUBLIC_CHAIN_TRANSACTIONS=0');
}

main().catch((error) => {
  writeJson('FAILURE.json', { verdict: 'FAILED', error: String(error?.stack ?? error), safety: { publicChainWrites: 0 } });
  console.error(error?.stack ?? error);
  process.exit(1);
});
