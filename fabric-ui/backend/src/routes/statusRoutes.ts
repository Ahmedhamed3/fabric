import { Router } from 'express';
import { FabricService } from '../services/fabricService.js';

export function statusRoutes(service: FabricService): Router {
  const router = Router();

  router.get('/overview', async (_req, res) => {
    const data = await service.getOverview();
    res.json(data);
  });

  router.get('/containers', async (_req, res) => {
    const data = await service.getContainers();
    res.json({ services: data });
  });

  router.get('/chaincode', async (_req, res) => {
    const data = await service.getChaincode();
    res.json(data);
  });

  router.get('/channels', async (_req, res) => {
    const data = await service.getChannels();
    res.json({ channels: data });
  });

  return router;
}
