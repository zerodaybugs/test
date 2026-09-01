import fs from "node:fs/promises";
import path from "node:path";
import util from "node:util";

import {
  Address,
  AssetName,
  ScriptHash,
  TransactionHash,
} from "@evolution-sdk/evolution";

import { ClientContext } from "./client.js";
import {
  Pyth_price_pyth_price_withdraw,
  Pyth_state_update_spend,
} from "./offchain.js";
import { SpendingValidator, WithdrawingValidator } from "./utils.js";

const POLICY = "c935c937d0deda8975142c7b77aeef8f8cd48791e89a8ca7a0edc154";
const ASSET_NAME = AssetName.toHex(
  AssetName.fromBytes(Buffer.from("Pyth State", "utf8")),
);
const UNIT = POLICY + ASSET_NAME;
const OUT_DIR = path.resolve(process.env.OUT_DIR ?? "./pyth-cardano-public-binding");
const READ_ONLY_MNEMONIC =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

const pythStateSpend = SpendingValidator.new(Pyth_state_update_spend);
const pythPriceWithdraw = WithdrawingValidator.new(
  Pyth_price_pyth_price_withdraw,
);

function hex(value: unknown): string | null {
  if (value instanceof Uint8Array || Buffer.isBuffer(value)) {
    return Buffer.from(value).toString("hex");
  }
  if (typeof value === "string") return value.replace(/^0x/, "");
  if (!value || typeof value !== "object") return null;
  for (const key of ["hash", "bytes", "value"]) {
    const candidate = (value as Record<string, unknown>)[key];
    if (candidate instanceof Uint8Array || Buffer.isBuffer(candidate)) {
      return Buffer.from(candidate).toString("hex");
    }
    if (typeof candidate === "string" && /^[0-9a-f]+$/i.test(candidate)) {
      return candidate.replace(/^0x/, "");
    }
  }
  return null;
}

function normalize(value: unknown, seen = new WeakSet<object>()): unknown {
  if (typeof value === "bigint") return value.toString();
  if (value instanceof Uint8Array || Buffer.isBuffer(value)) {
    return { hex: Buffer.from(value).toString("hex"), bytes: value.length };
  }
  if (value instanceof Map) {
    return [...value.entries()].map(([key, item]) => [
      normalize(key, seen),
      normalize(item, seen),
    ]);
  }
  if (value instanceof Set) return [...value].map((item) => normalize(item, seen));
  if (Array.isArray(value)) return value.map((item) => normalize(item, seen));
  if (value && typeof value === "object") {
    if (seen.has(value)) return "<cycle>";
    seen.add(value);
    const output: Record<string, unknown> = {};
    for (const key of Object.keys(value).sort()) {
      try {
        output[key] = normalize((value as Record<string, unknown>)[key], seen);
      } catch (error) {
        output[key] = `<read-error:${String(error)}>`;
      }
    }
    return output;
  }
  return value;
}

async function writeJson(name: string, value: unknown): Promise<void> {
  await fs.writeFile(
    path.join(OUT_DIR, name),
    `${JSON.stringify(normalize(value), null, 2)}\n`,
  );
}

async function postKoios(baseUrl: string): Promise<unknown> {
  // Koios expects each requested asset as a [policy_id, asset_name] pair.
  // Passing the concatenated Cardano unit string returns an empty result even
  // when the NFT exists, so keep the API request independent from the unit form
  // used by Evolution SDK and explorers.
  const response = await fetch(`${baseUrl}/asset_utxos`, {
    body: JSON.stringify({
      _asset_list: [[POLICY, ASSET_NAME]],
      _extended: true,
    }),
    headers: {
      accept: "application/json",
      "content-type": "application/json",
      range: "0-9",
    },
    method: "POST",
  });
  const text = await response.text();
  if (!response.ok) {
    throw new Error(`${baseUrl} returned HTTP ${response.status}: ${text}`);
  }
  return JSON.parse(text);
}

function firstUtxo(value: unknown): Record<string, unknown> {
  if (!Array.isArray(value) || value.length !== 1 || !value[0]) {
    throw new Error(`expected exactly one State NFT UTxO, got ${util.inspect(value)}`);
  }
  return value[0] as Record<string, unknown>;
}

function koiosIdentity(value: unknown) {
  const utxo = firstUtxo(value);
  return {
    address: utxo.address,
    datum_hash: utxo.datum_hash,
    inline_datum: utxo.inline_datum,
    payment_cred: utxo.payment_cred,
    reference_script: utxo.reference_script,
    tx_hash: utxo.tx_hash,
    tx_index: String(utxo.tx_index),
  };
}

function signerExpiry(range: any): string | null {
  const finite = range?.upper_bound?.bound_type?.finite;
  if (typeof finite === "bigint") return (finite / 1000n).toString();
  if (typeof finite === "number") return Math.floor(finite / 1000).toString();
  return null;
}

async function main() {
  await fs.mkdir(OUT_DIR, { recursive: true });

  const [koiosOfficial, koiosXray] = await Promise.all([
    postKoios("https://api.koios.rest/api/v1"),
    postKoios("https://graph.xray.app/output/services/koios/mainnet/api/v1"),
  ]);
  await writeJson("koios-official-asset-utxos.json", koiosOfficial);
  await writeJson("koios-xray-asset-utxos.json", koiosXray);

  const officialIdentity = koiosIdentity(koiosOfficial);
  const xrayIdentity = koiosIdentity(koiosXray);

  const ctx = await ClientContext.create(
    "mainnet",
    { token: "", type: "koios" },
    READ_ONLY_MNEMONIC,
    { debug: false },
  );
  const stateUtxo = await ctx.getNftUtxo(
    POLICY,
    AssetName.fromBytes(Buffer.from("Pyth State", "utf8")),
  );
  const datum = Pyth_state_update_spend.datum.fromData(
    ClientContext.readUtxo(stateUtxo),
  ) as any;

  const liveAddress = Address.toBech32((stateUtxo as any).address);
  const livePaymentCredential = hex(
    (stateUtxo as any).address?.paymentCredential,
  );
  const liveWithdrawScript = Buffer.from(datum.withdraw_script).toString("hex");
  const localSpendScript = ScriptHash.toHex(pythStateSpend.script().hash);
  const localWithdrawScript = ScriptHash.toHex(
    pythPriceWithdraw.script(Buffer.from(POLICY, "hex")).hash,
  );
  const txHash = TransactionHash.toHex((stateUtxo as any).transactionId);
  const txIndex = String((stateUtxo as any).index);

  const decodedSigners = [...(datum.trusted_signers as Map<Uint8Array, unknown>).entries()]
    .map(([key, range]) => ({
      expires_at: signerExpiry(range),
      public_key: Buffer.from(key).toString("hex"),
    }))
    .sort((a, b) => a.public_key.localeCompare(b.public_key));

  const snapshot = {
    captured_at: new Date().toISOString(),
    deployment: {
      asset_name_ascii: "Pyth State",
      asset_name_hex: ASSET_NAME,
      policy_id: POLICY,
      unit: UNIT,
    },
    live: {
      address: liveAddress,
      payment_credential: livePaymentCredential,
      transaction_id: txHash,
      transaction_index: txIndex,
      governance: {
        emitter_address: Buffer.from(datum.governance.emitter_address).toString("hex"),
        emitter_chain: datum.governance.emitter_chain.toString(),
        seen_sequence: datum.governance.seen_sequence.toString(),
        wormhole_policy: Buffer.from(datum.governance.wormhole).toString("hex"),
      },
      trusted_signers: decodedSigners,
      withdraw_script: liveWithdrawScript,
      deprecated_withdraw_scripts: normalize(datum.deprecated_withdraw_scripts),
      raw_utxo: normalize(stateUtxo),
    },
    local_exact_build: {
      spend_script_hash: localSpendScript,
      withdraw_script_hash: localWithdrawScript,
    },
    providers: {
      koios_official: officialIdentity,
      koios_xray: xrayIdentity,
    },
    comparisons: {
      koios_providers_identical:
        JSON.stringify(officialIdentity) === JSON.stringify(xrayIdentity),
      client_matches_koios_tx:
        String(officialIdentity.tx_hash) === txHash &&
        String(officialIdentity.tx_index) === txIndex,
      client_matches_koios_address: String(officialIdentity.address) === liveAddress,
      live_spend_script_matches_exact_source_build:
        livePaymentCredential?.toLowerCase() === localSpendScript.toLowerCase(),
      live_withdraw_script_matches_exact_source_build:
        liveWithdrawScript.toLowerCase() === localWithdrawScript.toLowerCase(),
    },
    explorer_urls: {
      cardanoscan_token: `https://cardanoscan.io/token/${UNIT}`,
      cardanoscan_transaction: `https://cardanoscan.io/transaction/${txHash}`,
      cexplorer_asset:
        "https://cexplorer.io/asset/asset1nup2062z9fmwlrp706aqx0462gs305zktegfn4/owner",
    },
  };

  await writeJson("deployment-binding.json", snapshot);
  await fs.writeFile(
    path.join(OUT_DIR, "BINDING_MARKERS.txt"),
    [
      `PYTH_CARDANO_POLICY=${POLICY}`,
      `STATE_TX=${txHash}#${txIndex}`,
      `STATE_ADDRESS=${liveAddress}`,
      `LIVE_PAYMENT_CREDENTIAL=${livePaymentCredential ?? "UNKNOWN"}`,
      `LOCAL_SPEND_SCRIPT=${localSpendScript}`,
      `LIVE_WITHDRAW_SCRIPT=${liveWithdrawScript}`,
      `LOCAL_WITHDRAW_SCRIPT=${localWithdrawScript}`,
      `SEEN_SEQUENCE=${datum.governance.seen_sequence.toString()}`,
      `WORMHOLE_POLICY=${Buffer.from(datum.governance.wormhole).toString("hex")}`,
      `KOIOS_PROVIDERS_IDENTICAL=${snapshot.comparisons.koios_providers_identical}`,
      `SPEND_BINDING_PASS=${snapshot.comparisons.live_spend_script_matches_exact_source_build}`,
      `WITHDRAW_BINDING_PASS=${snapshot.comparisons.live_withdraw_script_matches_exact_source_build}`,
      "PUBLIC_CHAIN_MODE=READ_ONLY",
      "",
    ].join("\n"),
  );

  const mandatory = [
    snapshot.comparisons.koios_providers_identical,
    snapshot.comparisons.client_matches_koios_tx,
    snapshot.comparisons.client_matches_koios_address,
    snapshot.comparisons.live_spend_script_matches_exact_source_build,
    snapshot.comparisons.live_withdraw_script_matches_exact_source_build,
  ];
  if (!mandatory.every(Boolean)) {
    throw new Error(`deployment binding failed: ${JSON.stringify(snapshot.comparisons)}`);
  }

  console.log("PYTH_CARDANO_DEPLOYMENT_BINDING_PASS");
}

main().catch(async (error) => {
  await fs.mkdir(OUT_DIR, { recursive: true });
  await fs.writeFile(
    path.join(OUT_DIR, "FATAL_ERROR.txt"),
    `${error instanceof Error ? `${error.name}: ${error.message}\n${error.stack ?? ""}` : util.inspect(error)}\n`,
  );
  console.error(error);
  process.exitCode = 1;
});
