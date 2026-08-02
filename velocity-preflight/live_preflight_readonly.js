#!/usr/bin/env node
'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { Connection, PublicKey } = require('@solana/web3.js');

const ROOT = path.resolve(__dirname);
const PROGRAM_ID = new PublicKey('vELoC1audYbSYVRXn1vPaV8Axoa9oU6BYmNGZZBDZ1P');
const EXPECTED_PROGRAMDATA = new PublicKey('HkRf36jvUB32dnHjHqpMnPcKJhUP2TUKJTH7RDTifJm7');
const EXPECTED_LOADER = new PublicKey('BPFLoaderUpgradeab1e11111111111111111111111');
const EXPECTED_DEPLOYMENT_SLOT = 435978201n;
const EXPECTED_CANONICAL_SHA256 = '1b7b06d17af813b5a505df8f534bfd0779a1a7457f0d2626b1a45c8741686c80';
const EXPECTED_CANONICAL_BYTES = 4523208;

function sha256(data) {
  return crypto.createHash('sha256').update(data).digest('hex');
}

function fail(message, details = {}) {
  const result = {
    PREFLIGHT_STATUS: 'FAIL',
    error: message,
    ...details,
    publicChainTransactions: 0,
  };
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  process.exitCode = 1;
}

function parseProgramAccount(data) {
  if (!Buffer.isBuffer(data) || data.length !== 36 || data.readUInt32LE(0) !== 2) {
    throw new Error('unexpected UpgradeableLoader Program account layout');
  }
  return new PublicKey(data.subarray(4, 36));
}

function canonicalElfLength(elfWithPadding) {
  if (elfWithPadding.length < 64 || !elfWithPadding.subarray(0, 4).equals(Buffer.from([0x7f, 0x45, 0x4c, 0x46]))) {
    throw new Error('ProgramData payload does not begin with ELF magic');
  }
  const elfClass = elfWithPadding[4];
  const endian = elfWithPadding[5];
  if (elfClass !== 2 || endian !== 1) {
    throw new Error(`unsupported ELF layout: class=${elfClass} endian=${endian}`);
  }
  const sectionOffset = Number(elfWithPadding.readBigUInt64LE(40));
  const sectionEntrySize = elfWithPadding.readUInt16LE(58);
  const sectionCount = elfWithPadding.readUInt16LE(60);
  const sectionEnd = sectionOffset + sectionEntrySize * sectionCount;
  if (!Number.isSafeInteger(sectionEnd) || sectionEnd <= 0 || sectionEnd > elfWithPadding.length) {
    throw new Error(`invalid ELF section-table end: ${sectionEnd}`);
  }
  return sectionEnd;
}

function parseProgramDataAccount(data) {
  if (!Buffer.isBuffer(data) || data.length < 45 || data.readUInt32LE(0) !== 3) {
    throw new Error('unexpected UpgradeableLoader ProgramData account layout');
  }
  const deploymentSlot = data.readBigUInt64LE(4);
  const authorityOption = data[12];
  const upgradeAuthority = authorityOption === 1 ? new PublicKey(data.subarray(13, 45)).toBase58() : null;
  const paddedPayload = data.subarray(45);
  const canonicalBytes = canonicalElfLength(paddedPayload);
  const canonicalElf = paddedPayload.subarray(0, canonicalBytes);
  const trailing = paddedPayload.subarray(canonicalBytes);
  return {
    deploymentSlot,
    authorityOption,
    upgradeAuthority,
    paddedPayload,
    canonicalBytes,
    canonicalElf,
    trailing,
  };
}

function evaluate({ endpoint, contextSlot, finalizedSlot, genesisHash, programInfo, programDataInfo }) {
  if (!programInfo) throw new Error('Velocity Program account not found');
  if (!programInfo.executable) throw new Error('Velocity Program account is not executable');
  if (!programInfo.owner.equals(EXPECTED_LOADER)) throw new Error(`unexpected Program owner: ${programInfo.owner.toBase58()}`);

  const programDataAddress = parseProgramAccount(Buffer.from(programInfo.data));
  if (!programDataAddress.equals(EXPECTED_PROGRAMDATA)) {
    throw new Error(`ProgramData address changed: ${programDataAddress.toBase58()}`);
  }
  if (!programDataInfo) throw new Error('Velocity ProgramData account not found');
  if (!programDataInfo.owner.equals(EXPECTED_LOADER)) throw new Error(`unexpected ProgramData owner: ${programDataInfo.owner.toBase58()}`);

  const parsed = parseProgramDataAccount(Buffer.from(programDataInfo.data));
  const canonicalSha256 = sha256(parsed.canonicalElf);
  const trailingAllZero = parsed.trailing.every((byte) => byte === 0);
  const localElfPath = path.join(ROOT, 'active_velocity.elf');
  const localElf = fs.readFileSync(localElfPath);
  const localElfSha256 = sha256(localElf);
  const localMatchesRemote = localElf.equals(parsed.canonicalElf);

  const gates = {
    programDataAddressMatches: programDataAddress.equals(EXPECTED_PROGRAMDATA),
    deploymentSlotMatches: parsed.deploymentSlot === EXPECTED_DEPLOYMENT_SLOT,
    canonicalBytesMatch: parsed.canonicalBytes === EXPECTED_CANONICAL_BYTES,
    canonicalSha256Matches: canonicalSha256 === EXPECTED_CANONICAL_SHA256,
    trailingPaddingAllZero,
    localPoCElfSha256Matches: localElfSha256 === EXPECTED_CANONICAL_SHA256,
    localPoCElfMatchesRemote: localMatchesRemote,
  };
  const pass = Object.values(gates).every(Boolean);

  return {
    PREFLIGHT_STATUS: pass ? 'PASS' : 'FAIL',
    mode: 'live_read_only',
    rpcEndpoint: endpoint,
    checkedAtUtc: new Date().toISOString(),
    contextSlot,
    finalizedSlot,
    genesisHash,
    programId: PROGRAM_ID.toBase58(),
    programDataAddress: programDataAddress.toBase58(),
    deploymentSlot: parsed.deploymentSlot.toString(),
    upgradeAuthorityOption: parsed.authorityOption,
    upgradeAuthority: parsed.upgradeAuthority,
    programDataAccountBytes: programDataInfo.data.length,
    paddedPayloadBytes: parsed.paddedPayload.length,
    canonicalElfBytes: parsed.canonicalBytes,
    canonicalElfSha256,
    trailingPaddingBytes: parsed.trailing.length,
    trailingPaddingAllZero,
    localPoCElfSha256: localElfSha256,
    gates,
    publicChainTransactions: 0,
  };
}

async function liveCheck() {
  const endpoints = [
    process.env.MAINNET_RPC_URL,
    'https://solana-rpc.publicnode.com',
    'https://api.mainnet-beta.solana.com',
    'https://solana.drpc.org',
    'https://1rpc.io/solana',
  ].filter(Boolean);
  let lastError;
  for (const endpoint of endpoints) {
    try {
      const connection = new Connection(endpoint, 'finalized');
      const [finalizedSlot, genesisHash, programResponse] = await Promise.all([
        connection.getSlot('finalized'),
        connection.getGenesisHash(),
        connection.getAccountInfoAndContext(PROGRAM_ID, 'finalized'),
      ]);
      const programInfo = programResponse.value;
      if (!programInfo) throw new Error('Velocity Program account not found');
      const programDataAddress = parseProgramAccount(Buffer.from(programInfo.data));
      const programDataResponse = await connection.getAccountInfoAndContext(programDataAddress, 'finalized');
      return evaluate({
        endpoint,
        contextSlot: Math.min(programResponse.context.slot, programDataResponse.context.slot),
        finalizedSlot,
        genesisHash,
        programInfo,
        programDataInfo: programDataResponse.value,
      });
    } catch (error) {
      lastError = error;
    }
  }
  throw lastError || new Error('no RPC endpoint available');
}

(async () => {
  try {
    const result = await liveCheck();
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    if (result.PREFLIGHT_STATUS !== 'PASS') process.exitCode = 1;
  } catch (error) {
    fail(error instanceof Error ? `${error.name}: ${error.message}` : String(error));
  }
})();
