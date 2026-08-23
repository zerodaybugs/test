import fs from 'node:fs';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { ethers } from 'ethers';
import { secp256k1 } from '@noble/curves/secp256k1';

const ROOT = process.env.TARGET_ROOT || process.cwd();
const OUT = process.env.OUT_DIR || path.join(process.cwd(), 'chronicle-gate-output');
fs.mkdirSync(OUT, { recursive: true });
const report = {
  targetCommit: process.env.TARGET_COMMIT || null,
  deployment: {},
  registration: {},
  signingCalibration: {},
  freshness: {},
  errors: [],
};
const write = () => fs.writeFileSync(path.join(OUT, 'freshness_gate.json'), JSON.stringify(report, null, 2) + '\n');
const fail = (stage, err) => {
  report.errors.push({ stage, message: String(err?.stack || err) });
  write();
};

const N = BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141');
const mod = (x) => ((x % N) + N) % N;
const toHex32 = (x) => ethers.zeroPadValue(ethers.toBeHex(x), 32);
const bytesToBigInt = (b) => BigInt(ethers.hexlify(b));
const pubXY = (privateKey) => {
  const raw = secp256k1.getPublicKey(ethers.getBytes(privateKey), false);
  return {
    x: bytesToBigInt(raw.slice(1, 33)),
    y: bytesToBigInt(raw.slice(33, 65)),
    raw,
  };
};
const pointAddress = (rawUncompressed) => ethers.getAddress('0x' + ethers.keccak256(rawUncompressed.slice(1)).slice(-40));

function findArtifact() {
  const candidates = [
    path.join(ROOT, 'out', 'Scribe.sol', 'Scribe.json'),
    path.join(ROOT, 'artifacts', 'src', 'Scribe.sol', 'Scribe.json'),
  ];
  for (const p of candidates) if (fs.existsSync(p)) return p;
  const stack = [path.join(ROOT, 'out'), path.join(ROOT, 'artifacts')].filter(fs.existsSync);
  while (stack.length) {
    const d = stack.pop();
    for (const e of fs.readdirSync(d, { withFileTypes: true })) {
      const p = path.join(d, e.name);
      if (e.isDirectory()) stack.push(p);
      else if (e.name === 'Scribe.json') return p;
    }
  }
  throw new Error('Scribe artifact not found');
}

function defaultFor(input, walletAddress) {
  const t = input.type;
  const n = (input.name || '').toLowerCase();
  if (t === 'address') return walletAddress;
  if (t === 'bool') return false;
  if (t === 'string') return 'ETH/USD';
  if (t === 'bytes') return '0x';
  if (t === 'bytes32') return ethers.id('ETH/USD');
  if (/^bytes\d+$/.test(t)) return ethers.zeroPadValue('0x00', Number(t.slice(5)));
  if (/^u?int\d*$/.test(t)) return 1n;
  if (t.endsWith('[]')) return [];
  if (t.startsWith('tuple')) return (input.components || []).map((c) => defaultFor(c, walletAddress));
  throw new Error(`No default for constructor input ${input.name}:${input.type}`);
}

function tupleByComponents(components, values) {
  return components.map((c) => {
    const n = (c.name || '').toLowerCase();
    if (n === 'x' || n.includes('pubkeyx')) return values.x;
    if (n === 'y' || n.includes('pubkeyy')) return values.y;
    if (n === 'v') return values.v;
    if (n === 'r') return values.r;
    if (n === 's') return values.s;
    if (n.includes('val')) return values.val;
    if (n.includes('age') || n.includes('time')) return values.age;
    if (n.includes('signature') || n === 'sig') return values.signature;
    if (n.includes('commitment')) return values.commitment;
    if (n.includes('feedids') || (n.includes('feed') && c.type === 'bytes')) return values.feedIds;
    if (c.type.startsWith('tuple')) return tupleByComponents(c.components || [], values);
    if (c.type === 'address') return values.address || ethers.ZeroAddress;
    if (c.type === 'bytes') return '0x';
    if (c.type === 'bytes32') return ethers.ZeroHash;
    if (/^u?int\d*$/.test(c.type)) return 0n;
    if (c.type.endsWith('[]')) return [];
    throw new Error(`Cannot populate tuple component ${c.name}:${c.type}`);
  });
}

function argsForFunction(fragment, values) {
  return fragment.inputs.map((input) => {
    const n = (input.name || '').toLowerCase();
    if (input.type.startsWith('tuple')) return tupleByComponents(input.components || [], values);
    if (n.includes('pubkey')) return [values.x, values.y];
    if (n === 'v') return values.v;
    if (n === 'r') return values.r;
    if (n === 's') return values.s;
    if (n.includes('val')) return values.val;
    if (n.includes('age')) return values.age;
    if (n.includes('signature') || n === 'sig') return values.signature;
    if (n.includes('commitment')) return values.commitment;
    if (n.includes('feedids') || (n.includes('feed') && input.type === 'bytes')) return values.feedIds;
    if (input.type === 'address') return values.address || ethers.ZeroAddress;
    if (input.type === 'bytes') return values.feedIds || '0x';
    if (input.type === 'bytes32') return values.signature || ethers.ZeroHash;
    if (/^u?int\d*$/.test(input.type)) return values.val ?? 0n;
    throw new Error(`Cannot populate input ${input.name}:${input.type}`);
  });
}

async function setNextTimestamp(provider, ts) {
  try {
    await provider.send('evm_setNextBlockTimestamp', [Number(ts)]);
  } catch {
    await provider.send('anvil_setNextBlockTimestamp', [Number(ts)]);
  }
}
async function mine(provider) { await provider.send('evm_mine', []); }
async function snapshot(provider) { return provider.send('evm_snapshot', []); }
async function revertTo(provider, id) { return provider.send('evm_revert', [id]); }

function findRegistrationGetter(contract) {
  const names = contract.interface.fragments
    .filter((f) => f.type === 'function' && f.outputs?.length === 1 && f.outputs[0].type === 'bytes32')
    .map((f) => f.name)
    .filter((n) => /registration|lift|feed.*message/i.test(n));
  return [...new Set(names)];
}

function sourceRegistrationDigest() {
  const files = ['src/Scribe.sol', 'src/IScribe.sol', 'src/libs/LibSchnorr.sol'].map((x) => path.join(ROOT, x)).filter(fs.existsSync);
  for (const f of files) {
    const text = fs.readFileSync(f, 'utf8');
    const literals = [...text.matchAll(/keccak256\s*\(\s*(?:abi\.encodePacked\s*\()?\s*["']([^"']{3,200})["']/g)];
    for (const m of literals) if (/feed|register|scribe|lift/i.test(m[1])) return ethers.keccak256(ethers.toUtf8Bytes(m[1]));
  }
  return null;
}

function challengeVariants(pub, message, commitment) {
  const parity = Number(pub.y & 1n);
  const variants = [];
  const add = (name, encoded) => variants.push({ name, e: BigInt(ethers.keccak256(encoded)) % N });
  add('packed-u256-u8-b32-address', ethers.solidityPacked(['uint256','uint8','bytes32','address'], [pub.x, parity, message, commitment]));
  add('abi-u256-u8-b32-address', ethers.AbiCoder.defaultAbiCoder().encode(['uint256','uint8','bytes32','address'], [pub.x, parity, message, commitment]));
  add('packed-u256-bool-b32-address', ethers.solidityPacked(['uint256','bool','bytes32','address'], [pub.x, Boolean(parity), message, commitment]));
  add('packed-u256-u256-b32-address', ethers.solidityPacked(['uint256','uint256','bytes32','address'], [pub.x, BigInt(parity), message, commitment]));
  return variants;
}

async function main() {
  const rpc = process.env.RPC_URL || 'http://127.0.0.1:8545';
  const provider = new ethers.JsonRpcProvider(rpc);
  const accounts = await provider.send('eth_accounts', []);
  const signer = await provider.getSigner(accounts[0]);
  const signerAddress = await signer.getAddress();
  const artifactPath = findArtifact();
  const artifact = JSON.parse(fs.readFileSync(artifactPath, 'utf8'));
  const abi = artifact.abi;
  const bytecode = artifact.bytecode?.object || artifact.bytecode;
  if (!bytecode || bytecode === '0x') throw new Error('Missing deploy bytecode');
  fs.writeFileSync(path.join(OUT, 'scribe_abi.json'), JSON.stringify(abi, null, 2) + '\n');

  const ctor = abi.find((x) => x.type === 'constructor') || { inputs: [] };
  const ctorArgs = (ctor.inputs || []).map((i) => defaultFor(i, signerAddress));
  const factory = new ethers.ContractFactory(abi, bytecode, signer);
  const contract = await factory.deploy(...ctorArgs);
  await contract.waitForDeployment();
  report.deployment = { artifactPath, address: await contract.getAddress(), constructorArgs: ctorArgs.map(String) };

  const functions = abi.filter((x) => x.type === 'function').map((x) => ({ name: x.name, inputs: x.inputs, outputs: x.outputs, stateMutability: x.stateMutability }));
  fs.writeFileSync(path.join(OUT, 'abi_functions.json'), JSON.stringify(functions, null, 2) + '\n');

  const feedPriv = '0x' + '11'.repeat(32);
  const feedWallet = new ethers.Wallet(feedPriv);
  const pub = pubXY(feedPriv);
  const feedAddress = pointAddress(pub.raw);
  if (ethers.getAddress(feedWallet.address) !== feedAddress) throw new Error('Public-key address mismatch');
  const feedId = '0x' + feedAddress.slice(2, 4);

  let registrationDigest = null;
  let registrationGetter = null;
  for (const name of findRegistrationGetter(contract)) {
    try {
      const v = await contract[name]();
      if (ethers.isHexString(v, 32)) { registrationDigest = v; registrationGetter = name; break; }
    } catch {}
  }
  if (!registrationDigest) registrationDigest = sourceRegistrationDigest();
  if (!registrationDigest) throw new Error('Could not resolve feed registration digest');
  const regSig = feedWallet.signingKey.sign(registrationDigest);
  const regValues = { x: pub.x, y: pub.y, v: regSig.v, r: regSig.r, s: regSig.s, address: feedAddress };
  const liftFragments = contract.interface.fragments.filter((f) => f.type === 'function' && f.name === 'lift');
  let liftUsed = null;
  const liftErrors = [];
  for (const frag of liftFragments) {
    try {
      const fn = contract.getFunction(frag.format('sighash'));
      const args = argsForFunction(frag, regValues);
      await fn.staticCall(...args);
      const tx = await fn(...args); await tx.wait();
      liftUsed = { signature: frag.format('sighash'), args: args.map((x) => JSON.stringify(x, (_,v)=>typeof v==='bigint'?v.toString():v)) };
      break;
    } catch (e) { liftErrors.push({ signature: frag.format('sighash'), error: String(e.shortMessage || e.message) }); }
  }
  report.registration = { registrationDigest, registrationGetter, feedAddress, feedId, liftUsed, liftErrors };
  if (!liftUsed) throw new Error('No lift overload succeeded');

  const setBarFrag = contract.interface.fragments.find((f) => f.type === 'function' && /setbar/i.test(f.name));
  if (!setBarFrag) throw new Error('setBar not found');
  await (await contract.getFunction(setBarFrag.format('sighash'))(1)).wait();

  const pokeFragments = contract.interface.fragments.filter((f) => f.type === 'function' && f.name === 'poke');
  const constructFragments = contract.interface.fragments.filter((f) => f.type === 'function' && /construct.*poke.*message/i.test(f.name));
  if (!pokeFragments.length) throw new Error('poke not found');

  const genesisBlock = await provider.getBlock('latest');
  let baseTs = BigInt(genesisBlock.timestamp) + 10n;

  async function constructMessage(val, age) {
    const values = { val, age };
    for (const frag of constructFragments) {
      try {
        const args = argsForFunction(frag, values);
        const m = await contract.getFunction(frag.format('sighash'))(...args);
        if (ethers.isHexString(m, 32)) return { message: m, method: frag.format('sighash') };
      } catch {}
    }
    let wat = ethers.id('ETH/USD');
    for (const name of ['wat','WAT']) {
      try { const x = await contract[name](); if (ethers.isHexString(x,32)) { wat=x; break; } } catch {}
    }
    const candidates = [
      { method: 'fallback-packed-bytes32-u128-u32', message: ethers.keccak256(ethers.solidityPacked(['bytes32','uint128','uint32'], [wat,val,age])) },
      { method: 'fallback-abi-bytes32-u128-u32', message: ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(['bytes32','uint128','uint32'], [wat,val,age])) },
      { method: 'fallback-packed-u128-u32', message: ethers.keccak256(ethers.solidityPacked(['uint128','uint32'], [val,age])) },
    ];
    return candidates[0];
  }

  const nonceK = BigInt('0x22' + '00'.repeat(31));
  const noncePriv = toHex32(mod(nonceK));
  const R = pubXY(noncePriv);
  const commitment = pointAddress(R.raw);

  async function buildSigned(val, age) {
    const messageCandidates = [];
    for (const frag of constructFragments) {
      try {
        const args = argsForFunction(frag, { val, age });
        const m = await contract.getFunction(frag.format('sighash'))(...args);
        if (ethers.isHexString(m, 32)) messageCandidates.push({ message: m, method: frag.format('sighash') });
      } catch {}
    }
    if (!messageCandidates.length) messageCandidates.push(await constructMessage(val, age));
    const attempts = [];
    for (const mc of messageCandidates) {
      for (const cv of challengeVariants(pub, mc.message, commitment)) {
        const formulas = [
          ['k_plus_ex', mod(nonceK + cv.e * BigInt(feedPriv))],
          ['k_minus_ex', mod(nonceK - cv.e * BigInt(feedPriv))],
          ['ex_minus_k', mod(cv.e * BigInt(feedPriv) - nonceK)],
          ['neg_k_plus_ex', mod(-nonceK + cv.e * BigInt(feedPriv))],
          ['neg_k_minus_ex', mod(-nonceK - cv.e * BigInt(feedPriv))],
        ];
        for (const [formula, sigInt] of formulas) {
          const values = { val, age, signature: toHex32(sigInt), commitment, feedIds: feedId };
          for (const frag of pokeFragments) {
            try {
              const fn = contract.getFunction(frag.format('sighash'));
              const args = argsForFunction(frag, values);
              await fn.staticCall(...args);
              return { values, args, frag, message: mc.message, messageMethod: mc.method, challengeVariant: cv.name, formula, challenge: cv.e.toString(), nonceK: nonceK.toString() };
            } catch (e) {
              attempts.push({ poke: frag.format('sighash'), messageMethod: mc.method, challengeVariant: cv.name, formula, error: String(e.shortMessage || e.message).slice(0,240) });
            }
          }
        }
      }
    }
    fs.writeFileSync(path.join(OUT, 'signature_attempts.json'), JSON.stringify(attempts, null, 2) + '\n');
    throw new Error('No Schnorr signing calibration succeeded');
  }

  await setNextTimestamp(provider, baseTs); await mine(provider);
  const initial = await buildSigned(100n, Number(baseTs));
  report.signingCalibration = { messageMethod: initial.messageMethod, challengeVariant: initial.challengeVariant, formula: initial.formula, pokeSignature: initial.frag.format('sighash') };
  await (await contract.getFunction(initial.frag.format('sighash'))(...initial.args)).wait();

  let stored = null;
  for (const name of ['readWithAge','tryReadWithAge']) {
    try { stored = await contract[name](); if (stored) break; } catch {}
  }
  const storedArray = stored ? Array.from(stored) : [];
  const storedAge0 = storedArray.length ? BigInt(storedArray[storedArray.length-1]) : baseTs;
  const delayedAge = storedAge0 + 1n;
  const freshAge = storedAge0 + 50n;
  const executionTs = storedAge0 + 100n;
  const delayed = await buildSigned(1n, Number(delayedAge));
  const fresh = await buildSigned(1000n, Number(freshAge));

  const snap = await snapshot(provider);
  await setNextTimestamp(provider, executionTs);
  const freshTx = await contract.getFunction(fresh.frag.format('sighash'))(...fresh.args); await freshTx.wait();
  let negativeFreshRead = null;
  try { negativeFreshRead = Array.from(await contract.readWithAge()).map(String); } catch {}
  await revertTo(provider, snap);

  await setNextTimestamp(provider, executionTs);
  const delayedTx = await contract.getFunction(delayed.frag.format('sighash'))(...delayed.args); await delayedTx.wait();
  let afterDelayed = null;
  try { afterDelayed = Array.from(await contract.readWithAge()).map(String); } catch {}
  let freshBlocked = false;
  let freshBlockError = null;
  try {
    const tx = await contract.getFunction(fresh.frag.format('sighash'))(...fresh.args); await tx.wait();
  } catch (e) { freshBlocked = true; freshBlockError = String(e.shortMessage || e.message); }

  const reportedAge = afterDelayed?.length ? BigInt(afterDelayed[afterDelayed.length-1]) : 0n;
  const reportedValue = afterDelayed?.length ? BigInt(afterDelayed[0]) : null;
  const rootCauseProven = freshBlocked && reportedValue === 1n && reportedAge >= executionTs && reportedAge > delayedAge;
  report.freshness = {
    initialStoredAge: storedAge0.toString(), delayedSignedAge: delayedAge.toString(), freshSignedAge: freshAge.toString(), executionTimestamp: executionTs.toString(),
    afterDelayed, negativeFreshRead, freshBlocked, freshBlockError,
    freshnessLaunderingSeconds: (reportedAge - delayedAge).toString(), rootCauseProven,
  };
  write();
  fs.writeFileSync(path.join(OUT, rootCauseProven ? 'ROOT_CAUSE_PROVEN.marker' : 'ROOT_CAUSE_NOT_PROVEN.marker'), rootCauseProven ? '1\n' : '0\n');
}

main().catch((e) => { fail('main', e); process.exitCode = 2; });
