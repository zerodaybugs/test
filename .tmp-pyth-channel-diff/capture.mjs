import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';

const OUT = path.resolve(process.env.OUT_DIR ?? 'evidence');
const ENDPOINT = 'https://docs.pyth.network/api/playground/stream';
const FEEDS = [1, 2, 6, 110];
const PROPERTIES = [
  'price',
  'bestBidPrice',
  'bestAskPrice',
  'confidence',
  'exponent',
  'feedUpdateTimestamp',
];
const CHANNELS = ['real_time', 'fixed_rate@200ms', 'fixed_rate@1000ms'];
const MAX_MESSAGES = Math.max(4, Math.min(100, Number(process.env.MAX_MESSAGES ?? 40)));
const MAX_DURATION_MS = Math.max(5000, Math.min(30000, Number(process.env.MAX_DURATION_MS ?? 18000)));

fs.mkdirSync(OUT, { recursive: true });
const sha256 = (value) => crypto.createHash('sha256').update(value).digest('hex');
const writeJson = (name, value) => fs.writeFileSync(path.join(OUT, name), JSON.stringify(value, null, 2) + '\n');

function extractSolanaHex(payload) {
  const candidates = [
    payload?.data?.value?.solana?.data,
    payload?.data?.solana?.data,
    payload?.value?.solana?.data,
    payload?.solana?.data,
  ];
  return candidates.find((value) => typeof value === 'string') ?? null;
}

function extractParsed(payload) {
  const candidates = [
    payload?.data?.value?.parsed,
    payload?.data?.parsed,
    payload?.value?.parsed,
    payload?.parsed,
  ];
  return candidates.find((value) => value && typeof value === 'object') ?? null;
}

async function captureChannel(channel) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), MAX_DURATION_MS);
  const request = {
    accessToken: '',
    priceFeedIds: FEEDS,
    properties: PROPERTIES,
    formats: ['solana'],
    channel,
    deliveryFormat: 'json',
    jsonBinaryEncoding: 'hex',
    parsed: true,
  };
  const output = {
    channel,
    request,
    startedAt: new Date().toISOString(),
    httpStatus: null,
    responseHeaders: {},
    events: [],
    messages: [],
    error: null,
  };
  try {
    const response = await fetch(ENDPOINT, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        accept: 'text/event-stream',
        'user-agent': 'Pyth-Official-Playground-Channel-Differential/1.0',
      },
      body: JSON.stringify(request),
      signal: controller.signal,
    });
    output.httpStatus = response.status;
    for (const [key, value] of response.headers.entries()) output.responseHeaders[key] = value;
    if (!response.ok || !response.body) {
      output.error = `HTTP ${response.status}: ${(await response.text()).slice(0, 1000)}`;
      return output;
    }

    const decoder = new TextDecoder();
    let buffer = '';
    let eventName = '';
    let dataLines = [];
    const consumeEvent = () => {
      if (!eventName && dataLines.length === 0) return;
      const rawData = dataLines.join('\n');
      let data = rawData;
      try { data = JSON.parse(rawData); } catch {}
      const row = { event: eventName || 'message', receivedAt: new Date().toISOString(), data };
      output.events.push(row);
      if (row.event === 'message') {
        const solanaHex = extractSolanaHex(data);
        const parsed = extractParsed(data);
        output.messages.push({
          receivedAt: row.receivedAt,
          solanaHex,
          solanaBytes: solanaHex ? solanaHex.length / 2 : null,
          solanaSha256: solanaHex ? sha256(Buffer.from(solanaHex, 'hex')) : null,
          parsed,
          raw: data,
        });
      }
      eventName = '';
      dataLines = [];
    };

    for await (const chunk of response.body) {
      buffer += decoder.decode(chunk, { stream: true });
      while (true) {
        const newline = buffer.indexOf('\n');
        if (newline < 0) break;
        const line = buffer.slice(0, newline).replace(/\r$/, '');
        buffer = buffer.slice(newline + 1);
        if (line === '') {
          consumeEvent();
          if (output.messages.length >= MAX_MESSAGES) {
            controller.abort();
            break;
          }
        } else if (line.startsWith('event:')) {
          eventName = line.slice(6).trim();
        } else if (line.startsWith('data:')) {
          dataLines.push(line.slice(5).trimStart());
        }
      }
      if (output.messages.length >= MAX_MESSAGES) break;
    }
    consumeEvent();
  } catch (error) {
    if (error?.name !== 'AbortError' || output.messages.length === 0) {
      output.error = String(error?.stack ?? error);
    }
  } finally {
    clearTimeout(timeout);
    output.finishedAt = new Date().toISOString();
    output.messageCount = output.messages.length;
  }
  return output;
}

function parsedTimestamp(message) {
  const parsed = message?.parsed;
  const value = parsed?.timestampUs ?? parsed?.timestamp_us ?? parsed?.timestamp;
  try { return value == null ? null : BigInt(value); } catch { return null; }
}

function feedMap(message) {
  const parsed = message?.parsed;
  const rows = parsed?.priceFeeds ?? parsed?.price_feeds ?? [];
  const map = new Map();
  for (const row of rows) {
    const id = Number(row.priceFeedId ?? row.price_feed_id ?? row.id);
    if (Number.isFinite(id)) map.set(id, row);
  }
  return map;
}

function numeric(value) {
  if (value == null) return null;
  const n = Number(value);
  return Number.isFinite(n) ? n : null;
}

function summarize(results) {
  const summaries = results.map((result) => ({
    channel: result.channel,
    httpStatus: result.httpStatus,
    messageCount: result.messages.length,
    errors: result.error,
    uniquePayloads: new Set(result.messages.map((row) => row.solanaSha256).filter(Boolean)).size,
    firstTimestampUs: result.messages.map(parsedTimestamp).filter((x) => x !== null).sort((a, b) => a < b ? -1 : 1)[0]?.toString() ?? null,
    lastTimestampUs: result.messages.map(parsedTimestamp).filter((x) => x !== null).sort((a, b) => a < b ? -1 : 1).at(-1)?.toString() ?? null,
  }));

  const comparisons = [];
  const base = results.find((row) => row.channel === 'fixed_rate@200ms');
  if (base) {
    for (const other of results.filter((row) => row !== base)) {
      for (const message of other.messages) {
        const ts = parsedTimestamp(message);
        if (ts === null) continue;
        const nearest = base.messages
          .map((candidate) => ({ candidate, ts: parsedTimestamp(candidate) }))
          .filter((row) => row.ts !== null)
          .sort((a, b) => {
            const da = a.ts > ts ? a.ts - ts : ts - a.ts;
            const db = b.ts > ts ? b.ts - ts : ts - b.ts;
            return da < db ? -1 : da > db ? 1 : 0;
          })[0];
        if (!nearest) continue;
        const aFeeds = feedMap(message);
        const bFeeds = feedMap(nearest.candidate);
        for (const feedId of FEEDS) {
          const a = aFeeds.get(feedId);
          const b = bFeeds.get(feedId);
          if (!a || !b) continue;
          const aPrice = numeric(a.price);
          const bPrice = numeric(b.price);
          if (aPrice == null || bPrice == null || bPrice === 0) continue;
          const timestampDeltaUs = ts > nearest.ts ? ts - nearest.ts : nearest.ts - ts;
          comparisons.push({
            channel: other.channel,
            feedId,
            timestampUs: ts.toString(),
            baselineTimestampUs: nearest.ts.toString(),
            timestampDeltaUs: timestampDeltaUs.toString(),
            price: aPrice,
            baselinePrice: bPrice,
            priceDiffBps: (aPrice - bPrice) / bPrice * 10000,
            feedUpdateTimestamp: String(a.feedUpdateTimestamp ?? a.feed_update_timestamp ?? ''),
            baselineFeedUpdateTimestamp: String(b.feedUpdateTimestamp ?? b.feed_update_timestamp ?? ''),
            solanaSha256: message.solanaSha256,
          });
        }
      }
    }
  }
  comparisons.sort((a, b) => Math.abs(b.priceDiffBps) - Math.abs(a.priceDiffBps));
  return {
    verdict: results.every((row) => row.httpStatus === 200 && row.messages.length > 0)
      ? 'PASS_OFFICIAL_PYTH_MULTI_CHANNEL_CAPTURE'
      : 'INCOMPLETE_OFFICIAL_PYTH_MULTI_CHANNEL_CAPTURE',
    endpoint: ENDPOINT,
    feeds: FEEDS,
    properties: PROPERTIES,
    channels: CHANNELS,
    summaries,
    comparisonCount: comparisons.length,
    strongestPriceDifferences: comparisons.slice(0, 200),
    publicChainTransactionsSigned: 0,
    publicChainTransactionsSent: 0,
    publicChainWrites: 0,
  };
}

const results = await Promise.all(CHANNELS.map(captureChannel));
for (const result of results) writeJson(`CHANNEL_${result.channel.replaceAll(/[^A-Za-z0-9]+/g, '_')}.json`, result);
const summary = summarize(results);
writeJson('SUMMARY.json', summary);
console.log(JSON.stringify(summary, null, 2));
if (summary.verdict !== 'PASS_OFFICIAL_PYTH_MULTI_CHANNEL_CAPTURE') process.exitCode = 2;
