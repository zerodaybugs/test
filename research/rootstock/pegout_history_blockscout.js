'use strict';

const fs = require('fs');
const path = require('path');
const { JsonRpcProvider, Interface, Contract, id } = require('ethers');

const OUT = process.env.OUT;
const BLOCKSCOUT = 'https://rootstock.blockscout.com';
const RPC = 'https://public-node.rsk.co';
const PEGOUT = '0x9A0678742cfb567874eb4e99Df2106BDED78F5E4';
const DISCOVERY = '0x9A48C6b18Aa000d0bd35D55616bCc98aD3553e7a';
const FROM_BLOCK = 8893303;

const tuple = '(uint256 chainId,uint256 callFee,uint256 penaltyFee,uint256 value,uint256 gasFee,address lbcAddress,address lpRskAddress,address rskRefundAddress,int64 nonce,uint32 agreementTimestamp,uint32 depositDateLimit,uint32 transferTime,uint32 expireDate,uint32 expireBlock,uint16 depositConfirmations,uint16 transferConfirmations,bytes depositAddress,bytes btcRefundAddress,bytes lpBtcAddress)';
const iface = new Interface([
  `function depositPegOut(${tuple} quote,bytes signature) payable`,
  'event PegOutDeposit(bytes32 indexed quoteHash,address indexed sender,uint256 indexed timestamp,uint256 amount)',
  'event PegOutRefunded(bytes32 indexed quoteHash)',
  'event PegOutUserRefunded(bytes32 indexed quoteHash,address indexed userAddress,uint256 indexed value)',
]);
const discoveryAbi = ['function getProviders() view returns ((uint256 id,address providerAddress,bool status,uint8 providerType,string name,string apiBaseUrl)[])'];
const topics = {
  deposit: id('PegOutDeposit(bytes32,address,uint256,uint256)'),
  lpRefund: id('PegOutRefunded(bytes32)'),
  userRefund: id('PegOutUserRefunded(bytes32,address,uint256)'),
};

function replacer(_key, value) {
  return typeof value === 'bigint' ? value.toString() : value;
}

async function fetchJson(url) {
  let last;
  for (let attempt = 1; attempt <= 4; attempt++) {
    try {
      const response = await fetch(url, {
        method: 'GET',
        redirect: 'error',
        headers: { accept: 'application/json', 'user-agent': 'Rootstock-authorized-readonly-research/1.0' },
        signal: AbortSignal.timeout(30000),
      });
      const text = await response.text();
      if (!response.ok) throw new Error(`HTTP ${response.status}: ${text.slice(0, 400)}`);
      return JSON.parse(text);
    } catch (error) {
      last = error;
      if (attempt < 4) await new Promise((resolve) => setTimeout(resolve, attempt * 600));
    }
  }
  throw last;
}

async function legacyLogs(topic0) {
  const url = new URL('/api', BLOCKSCOUT);
  for (const [key, value] of Object.entries({
    module: 'logs', action: 'getLogs', fromBlock: FROM_BLOCK, toBlock: 'latest', address: PEGOUT, topic0,
  })) url.searchParams.set(key, String(value));
  const body = await fetchJson(url.toString());
  fs.writeFileSync(path.join(OUT, `legacy-${topic0.slice(2, 10)}.json`), JSON.stringify(body, null, 2) + '\n');
  if (body.status === '0' && /No records/i.test(String(body.message) + String(body.result))) return [];
  if (!Array.isArray(body.result)) throw new Error(`unexpected legacy logs response: ${JSON.stringify(body).slice(0, 500)}`);
  return body.result;
}

async function mapLimit(items, limit, worker) {
  const results = new Array(items.length);
  let next = 0;
  async function run() {
    while (true) {
      const index = next++;
      if (index >= items.length) return;
      results[index] = await worker(items[index], index);
    }
  }
  await Promise.all(Array.from({ length: Math.min(limit, Math.max(items.length, 1)) }, run));
  return results;
}

async function main() {
  fs.mkdirSync(OUT, { recursive: true });
  const rpc = new JsonRpcProvider(RPC, undefined, { staticNetwork: false });
  const [network, latest, depositLogs, lpRefundLogs, userRefundLogs] = await Promise.all([
    rpc.getNetwork(), rpc.getBlockNumber(), legacyLogs(topics.deposit), legacyLogs(topics.lpRefund), legacyLogs(topics.userRefund),
  ]);

  const discovery = new Contract(DISCOVERY, discoveryAbi, rpc);
  const providerRows = await discovery.getProviders();
  const providerByAddress = {};
  for (const row of providerRows) {
    providerByAddress[row.providerAddress.toLowerCase()] = {
      id: row.id.toString(), name: row.name, apiBaseUrl: row.apiBaseUrl,
      providerType: Number(row.providerType), status: Boolean(row.status),
    };
  }

  const completions = {};
  for (const log of lpRefundLogs) completions[String(log.topics[1]).toLowerCase()] = { type: 'LP_REFUND', transactionHash: log.transactionHash, blockNumber: Number(log.blockNumber) };
  for (const log of userRefundLogs) completions[String(log.topics[1]).toLowerCase()] = { type: 'USER_REFUND', transactionHash: log.transactionHash, blockNumber: Number(log.blockNumber), userAddressTopic: log.topics[2], valueTopic: log.topics[3] };

  const blockCache = new Map();
  async function block(number) {
    if (!blockCache.has(number)) blockCache.set(number, rpc.getBlock(number));
    return blockCache.get(number);
  }

  const quotes = await mapLimit(depositLogs, 4, async (log) => {
    const txHash = log.transactionHash;
    const blockNumber = Number(log.blockNumber);
    const tx = await rpc.getTransaction(txHash);
    if (!tx) throw new Error(`missing transaction ${txHash}`);
    const parsed = iface.parseTransaction({ data: tx.data, value: tx.value });
    if (!parsed || parsed.name !== 'depositPegOut') throw new Error(`not depositPegOut: ${txHash}`);
    const q = parsed.args.quote;
    const depositBlock = await block(blockNumber);
    const quoteHash = String(log.topics[1]).toLowerCase();
    const completion = completions[quoteHash] || null;
    if (completion) {
      const completionBlock = await block(completion.blockNumber);
      completion.blockTimestamp = Number(completionBlock.timestamp);
      completion.secondsAfterDeposit = Number(completionBlock.timestamp) - Number(depositBlock.timestamp);
      completion.blocksAfterDeposit = completion.blockNumber - blockNumber;
    }
    const depositTimestamp = Number(depositBlock.timestamp);
    const valueWei = q.value;
    return {
      quoteHash, depositTransactionHash: txHash, depositBlockNumber: blockNumber, depositBlockTimestamp: depositTimestamp,
      provider: providerByAddress[q.lpRskAddress.toLowerCase()] || null,
      quote: {
        chainId: q.chainId.toString(), callFee: q.callFee.toString(), penaltyFee: q.penaltyFee.toString(), value: valueWei.toString(), gasFee: q.gasFee.toString(),
        lbcAddress: q.lbcAddress, lpRskAddress: q.lpRskAddress, rskRefundAddress: q.rskRefundAddress, nonce: q.nonce.toString(),
        agreementTimestamp: Number(q.agreementTimestamp), depositDateLimit: Number(q.depositDateLimit), transferTime: Number(q.transferTime),
        expireDate: Number(q.expireDate), expireBlock: Number(q.expireBlock), depositConfirmations: Number(q.depositConfirmations),
        transferConfirmations: Number(q.transferConfirmations), depositAddress: q.depositAddress, btcRefundAddress: q.btcRefundAddress, lpBtcAddress: q.lpBtcAddress,
      },
      derived: {
        valueRbtc: Number(valueWei) / 1e18,
        expireAfterDepositSeconds: Number(q.expireDate) - depositTimestamp,
        expireAfterDepositBlocks: Number(q.expireBlock) - blockNumber,
        proofSecondsAt10mBtcBlocks: Number(q.transferConfirmations) * 600,
        proofSecondsAt20mBtcBlocks: Number(q.transferConfirmations) * 1200,
        marginAt10mBtcBlocks: Number(q.expireDate) - depositTimestamp - Number(q.transferConfirmations) * 600,
        marginAt20mBtcBlocks: Number(q.expireDate) - depositTimestamp - Number(q.transferConfirmations) * 1200,
      },
      completion,
    };
  });
  quotes.sort((a, b) => a.depositBlockNumber - b.depositBlockNumber);

  const output = {
    generatedAt: new Date().toISOString(), mode: 'read-only Blockscout GET plus Rootstock JSON-RPC reads; no quote requested and no transaction submitted',
    chainId: network.chainId.toString(), latestBlock: latest, pegoutContract: PEGOUT, discoveryContract: DISCOVERY,
    eventCounts: { deposits: depositLogs.length, lpRefunds: lpRefundLogs.length, userRefunds: userRefundLogs.length }, providers: providerByAddress, quotes,
  };
  fs.writeFileSync(path.join(OUT, 'pegout-history.json'), JSON.stringify(output, replacer, 2) + '\n');
  const summary = quotes.map((row) => ({
    quoteHash: row.quoteHash, tx: row.depositTransactionHash, block: row.depositBlockNumber,
    provider: row.provider?.name || row.quote.lpRskAddress, valueRbtc: row.derived.valueRbtc,
    depositConfirmations: row.quote.depositConfirmations, transferConfirmations: row.quote.transferConfirmations,
    transferTimeSeconds: row.quote.transferTime, expireAfterDepositSeconds: row.derived.expireAfterDepositSeconds,
    expireAfterDepositBlocks: row.derived.expireAfterDepositBlocks, completionType: row.completion?.type || null,
    completionSecondsAfterDeposit: row.completion?.secondsAfterDeposit ?? null,
    marginAt10mBtcBlocks: row.derived.marginAt10mBtcBlocks, marginAt20mBtcBlocks: row.derived.marginAt20mBtcBlocks,
  }));
  fs.writeFileSync(path.join(OUT, 'SUMMARY.json'), JSON.stringify(summary, null, 2) + '\n');
  fs.writeFileSync(path.join(OUT, 'RESULT.txt'), `PASS\ndeposits=${quotes.length}\n`);
  console.log(JSON.stringify({ eventCounts: output.eventCounts, summary }, null, 2));
}

main().catch((error) => {
  fs.mkdirSync(OUT, { recursive: true });
  fs.writeFileSync(path.join(OUT, 'ERROR.txt'), String(error.stack || error) + '\n');
  fs.writeFileSync(path.join(OUT, 'RESULT.txt'), 'FAIL\n');
  console.error(error.stack || error);
  process.exitCode = 1;
});
