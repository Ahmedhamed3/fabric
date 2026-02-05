import express from 'express';
import cors from 'cors';
import { config } from './config.js';
import { FabricService } from './services/fabricService.js';
import { statusRoutes } from './routes/statusRoutes.js';
import { adminRoutes } from './routes/adminRoutes.js';
const app = express();
const service = new FabricService();
app.use(cors({ origin: config.frontendOrigin }));
app.use(express.json());
app.get('/health', (_req, res) => res.json({ ok: true }));
app.use('/api/status', statusRoutes(service));
app.use('/api/admin', adminRoutes(service));
async function bootstrap() {
    console.log('[fabric-ui] Bootstrapping Fabric network via start_socnet.sh...');
    await service.ensureNetworkStarted();
    console.log('[fabric-ui] Fabric bootstrap command completed. Starting API server...');
    setInterval(async () => {
        try {
            await service.getOverview();
        }
        catch {
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
