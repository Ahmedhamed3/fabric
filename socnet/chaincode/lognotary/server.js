'use strict';

const shim = require('fabric-shim');
const LogNotaryChaincode = require('./lib/lognotary');

const address = process.env.CHAINCODE_SERVER_ADDRESS || '0.0.0.0:9999';
const ccid = process.env.CHAINCODE_ID;

if (!ccid) {
  console.warn('CHAINCODE_ID is not set; peers will be unable to connect.');
}

const server = shim.server(new LogNotaryChaincode(), {
  ccid,
  address,
  tlsProps: { disabled: true }
});

server.start();
console.log(`LogNotary CCaaS server started on ${address}`);
