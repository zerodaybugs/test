'use strict';
const sdk = require('@defillama/sdk');

// Compatibility shim: the gate expects the legacy api.util.getLogs shape.
// Use the current indexed getEventLogs implementation without tuple parsing,
// preserving raw topics for MarketCreated address extraction.
sdk.api.util = sdk.api.util || {};
sdk.api.util.getLogs = async function getLogsCompat(options) {
  const logs = await sdk.getEventLogs({
    chain: options.chain,
    target: options.target,
    topic: options.topic,
    fromBlock: options.fromBlock,
    toBlock: options.toBlock,
    entireLog: true,
    parseLog: false,
    skipCache: true,
    maxBlockRange: 100000,
  });
  return { output: logs };
};

require('./zero_price_market_gate.js');
