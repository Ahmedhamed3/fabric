'use strict';

const { ChaincodeServer } = require('fabric-shim');
const LogNotaryChaincode = require('./lib/lognotary');

const address = process.env.CHAINCODE_SERVER_ADDRESS || '0.0.0.0:9999';
const chaincodeId = process.env.CHAINCODE_ID;

if (!chaincodeId) {
  console.warn('CHAINCODE_ID is not set; peers will be unable to connect.');
}

const server = new ChaincodeServer({
  chaincode: new LogNotaryChaincode(),
  address,
  chaincodeId,
  tlsProps: {
    disabled: true
  }
});

server.start()
  .then(() => {
    console.log(`LogNotary CCaaS server started on ${address}`);
  })
  .catch(err => {
    console.error('Failed to start CCaaS server:', err);
    process.exit(1);
  });
