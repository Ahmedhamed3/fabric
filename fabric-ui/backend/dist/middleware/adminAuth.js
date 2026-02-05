import { config } from '../config.js';
export function adminAuth(req, res, next) {
    const pass = req.header('x-admin-password');
    if (!pass || pass !== config.adminPassword) {
        res.status(401).json({ error: 'Unauthorized admin access' });
        return;
    }
    next();
}
