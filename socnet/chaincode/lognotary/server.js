'use strict';

const { ChaincodeServer } = require('fabric-shim');
const { LogNotaryContract } = require('./index');

const server = new ChaincodeServer({
  chaincode: new LogNotaryContract(),
  address: process.env.CHAINCODE_SERVER_ADDRESS || '0.0.0.0:9999',
  tlsProps: {
    disabled: true
  }
});

server.start()
  .then(() => {
    console.log('LogNotary CCaaS server started');
  })
  .catch(err => {
    console.error('Failed to start CCaaS server:', err);
    process.exit(1);
  });

