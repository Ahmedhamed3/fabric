import { Router } from 'express';
import { adminAuth } from '../middleware/adminAuth.js';
export function adminRoutes(service) {
    const router = Router();
    router.use(adminAuth);
    router.post('/restart', async (req, res) => {
        const { service: target } = req.body;
        if (!target) {
            return res.status(400).json({ ok: false, message: 'service is required' });
        }
        const result = await service.restartService(target);
        return res.status(result.ok ? 200 : 400).json(result);
    });
    router.get('/logs', async (req, res) => {
        const serviceName = req.query.service;
        const tail = Number(req.query.tail ?? 200);
        if (!serviceName) {
            return res.status(400).json({ ok: false, output: 'service query is required' });
        }
        const result = await service.getLogs(serviceName, tail);
        return res.status(result.ok ? 200 : 400).json(result);
    });
    return router;
}
