'use strict';

const { Contract } = require('fabric-contract-api');

class LogNotaryContract extends Contract {

  async InitLedger(ctx) {
    return 'Ledger initialized';
  }

  async PutEvidence(ctx, id, hash) {
    await ctx.stub.putState(id, Buffer.from(hash));
    return 'OK';
  }

  async GetEvidence(ctx, id) {
    const data = await ctx.stub.getState(id);
    if (!data || data.length === 0) {
      throw new Error(`Evidence ${id} not found`);
    }
    return data.toString();
  }
}

module.exports = { LogNotaryContract };

