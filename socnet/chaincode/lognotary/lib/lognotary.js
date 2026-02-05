'use strict';

const shim = require('fabric-shim');

class LogNotaryChaincode {
  async Init(stub) {
    return shim.success();
  }

  async Invoke(stub) {
    const { fcn, params } = stub.getFunctionAndParameters();

    switch (fcn) {
      case 'PutLog':
        return this.putLog(stub, params);
      case 'GetLog':
        return this.getLog(stub, params);
      default:
        return shim.error(new Error(`Unknown function: ${fcn}`));
    }
  }

  async putLog(stub, params) {
    if (params.length < 2) {
      return shim.error(new Error('PutLog requires key and value'));
    }

    const [key, value] = params;
    await stub.putState(key, Buffer.from(value));
    return shim.success();
  }

  async getLog(stub, params) {
    if (params.length < 1) {
      return shim.error(new Error('GetLog requires key'));
    }

    const [key] = params;
    const data = await stub.getState(key);
    if (!data || data.length === 0) {
      return shim.error(new Error(`Log ${key} not found`));
    }

    return shim.success(data);
  }
}

module.exports = LogNotaryChaincode;
