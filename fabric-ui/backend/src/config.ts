import path from 'node:path';
import dotenv from 'dotenv';

dotenv.config();

const socnetDir = process.env.SOCNET_DIR ?? '/opt/fabric-dev/socnet';
const repoRoot = path.resolve(socnetDir, '..');
const composeDir = process.env.COMPOSE_DIR ?? path.join(socnetDir, 'compose');

export const config = {
  port: Number(process.env.PORT ?? 4000),
  frontendOrigin: process.env.FRONTEND_ORIGIN ?? 'http://localhost:5173',
  adminPassword: process.env.ADMIN_PASSWORD ?? 'changeme',
  allowCoreRestart: process.env.ALLOW_CORE_RESTART === 'true',
  socnetDir,
  composeDir,
  startScript: process.env.START_SCRIPT ?? path.join(socnetDir, 'start_socnet.sh'),
  fabricBinDir: process.env.FABRIC_BIN_DIR ?? '/opt/fabric-dev/tools-fabric-3/fabric-samples/bin',
  fabricCfgPath: process.env.FABRIC_CFG_PATH ?? path.join(repoRoot, 'config'),
  fabricEnvScript: process.env.FABRIC_ENV_SCRIPT ?? path.join(composeDir, 'env_org1.sh'),
  fabricEnvScriptOrg2: process.env.FABRIC_ENV_SCRIPT_ORG2 ?? path.join(composeDir, 'env_org2.sh'),
  channel: process.env.CHANNEL_NAME ?? 'soclogs',
  ccName: process.env.CHAINCODE_NAME ?? 'lognotary',
  ccLabel: process.env.CHAINCODE_LABEL ?? 'lognotary_1.0',
  ccContainer: process.env.CHAINCODE_CONTAINER ?? 'lognotary-ccaas',
  ccEndpoint: process.env.CHAINCODE_ENDPOINT ?? 'lognotary-ccaas:9999',
  pollMs: Number(process.env.EVENT_POLL_MS ?? 10000)
};

export const requiredServices = [
  'orderer.example.com',
  'peer0.org1.example.com',
  'peer0.org2.example.com',
  config.ccContainer
];
