import { Router } from 'express';
import { FabricService } from '../services/fabricService.js';

const parsePositiveInt = (value: unknown, fallback: number): number => {
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed < 0) return fallback;
  return Math.floor(parsed);
};

export function v1Routes(service: FabricService): Router {
  const router = Router();

  router.get('/explorer/blocks', async (req, res) => {
    try {
      const channel = String(req.query.channel ?? 'soclogs');
      const limit = parsePositiveInt(req.query.limit, 20);
      const from = req.query.from !== undefined ? parsePositiveInt(req.query.from, 0) : undefined;
      const data = await service.getExplorerBlocks(channel, limit, from);
      res.json(data);
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  router.get('/explorer/blocks/:number', async (req, res) => {
    try {
      const channel = String(req.query.channel ?? 'soclogs');
      const number = parsePositiveInt(req.params.number, 0);
      const data = await service.getExplorerBlockDetail(channel, number);
      res.json(data);
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  router.get('/explorer/tx/:txid', async (req, res) => {
    try {
      const channel = String(req.query.channel ?? 'soclogs');
      const txid = String(req.params.txid);
      const data = await service.getTransactionDetail(channel, txid);
      res.json(data);
    } catch (error) {
      res.status(404).json({ error: (error as Error).message });
    }
  });

  router.get('/chaincode/definition', async (req, res) => {
    try {
      const channel = String(req.query.channel ?? 'soclogs');
      const name = String(req.query.name ?? 'lognotary');
      const data = await service.getChaincodeDefinition(channel, name);
      res.json(data);
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  router.get('/chaincode/invocations', async (req, res) => {
    try {
      const channel = String(req.query.channel ?? 'soclogs');
      const name = String(req.query.name ?? 'lognotary');
      const limit = parsePositiveInt(req.query.limit, 50);
      const data = await service.getChaincodeInvocations(channel, name, limit);
      res.json(data);
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  router.get('/audit/export/block/:number', async (req, res) => {
    try {
      const channel = String(req.query.channel ?? 'soclogs');
      const number = parsePositiveInt(req.params.number, 0);
      const data = await service.exportBlockBundle(channel, number);
      res.json(data);
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  router.get('/audit/export/tx/:txid', async (req, res) => {
    try {
      const channel = String(req.query.channel ?? 'soclogs');
      const txid = String(req.params.txid);
      const data = await service.exportTxBundle(channel, txid);
      res.json(data);
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  return router;
}
