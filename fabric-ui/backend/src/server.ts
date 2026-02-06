import express from 'express';
import cors from 'cors';
import { config } from './config.js';
import { FabricService } from './services/fabricService.js';
import { statusRoutes } from './routes/statusRoutes.js';
import { adminRoutes } from './routes/adminRoutes.js';
import { v1Routes } from './routes/v1Routes.js';

const app = express();
const service = new FabricService();

app.use(cors({ origin: config.frontendOrigin }));
app.use(express.json());

app.get('/health', async (_req, res) => {
  const status = await service.checkPeerHealth();
  res.status(status.ok ? 200 : 503).json(status);
});
app.use('/api/status', statusRoutes(service));
app.use('/api/admin', adminRoutes(service));
app.use('/api/v1', v1Routes(service));

async function bootstrap() {
  console.log('[fabric-ui] Bootstrapping Fabric network via start_socnet.sh...');
  await service.ensureNetworkStarted();
  console.log('[fabric-ui] Fabric bootstrap command completed. Starting API server...');
  await service.logFabricDiagnostics();

  setInterval(async () => {
    try {
      await service.getOverview();
    } catch {
      // ignore, surfaced in endpoint call
    }
  }, config.pollMs).unref();

  app.listen(config.port, () => {
    console.log(`[fabric-ui] Backend listening on :${config.port}`);
  });
}

bootstrap().catch((err) => {
  console.error('[fabric-ui] Failed to start backend', err);
  process.exit(1);
});
