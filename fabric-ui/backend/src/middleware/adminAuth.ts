import { Request, Response, NextFunction } from 'express';
import { config } from '../config.js';

export function adminAuth(req: Request, res: Response, next: NextFunction): void {
  const pass = req.header('x-admin-password');
  if (!pass || pass !== config.adminPassword) {
    res.status(401).json({ error: 'Unauthorized admin access' });
    return;
  }
  next();
}
