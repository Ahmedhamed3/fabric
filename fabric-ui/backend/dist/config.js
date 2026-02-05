import dotenv from 'dotenv';
dotenv.config();
export const config = {
    port: Number(process.env.PORT ?? 4000),
    frontendOrigin: process.env.FRONTEND_ORIGIN ?? 'http://localhost:5173',
    adminPassword: process.env.ADMIN_PASSWORD ?? 'changeme',
    allowCoreRestart: process.env.ALLOW_CORE_RESTART === 'true',
    socnetDir: process.env.SOCNET_DIR ?? '/opt/fabric-dev/socnet',
    composeDir: process.env.COMPOSE_DIR ?? '/opt/fabric-dev/socnet/compose',
    startScript: process.env.START_SCRIPT ?? '/opt/fabric-dev/socnet/start_socnet.sh',
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
