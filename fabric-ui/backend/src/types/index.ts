export type Health = 'Healthy' | 'Degraded';

export interface CommandResult {
  stdout: string;
  stderr: string;
  exitCode: number;
  timedOut: boolean;
}

export interface ServiceContainerStatus {
  name: string;
  status: string;
  uptime: string;
  network: string;
  ports: string;
  ip: string;
  running: boolean;
}

export interface ChaincodeStatus {
  name: string;
  version: string | null;
  sequence: string | null;
  initRequired: string | null;
  packageId: string | null;
  endpoint: string;
  ccaaSReachable: boolean;
  readyForEndorsements: boolean;
  errors: string[];
}

export interface Overview {
  network: string;
  channels: string[];
  overallStatus: Health;
  lastRefreshTime: string;
  summary: {
    peersUp: number;
    peersDown: number;
    ordererUp: number;
    ordererDown: number;
    channelsCount: number;
    chaincodesCount: number;
    ccaaSReachable: boolean;
    blockHeights: Record<string, number | null>;
  };
  organizations: Array<{
    name: string;
    mspId: string;
    peers: string[];
    status: Health;
  }>;
  services: ServiceContainerStatus[];
  chaincode: ChaincodeStatus;
  latestEvents: Array<{
    type: string;
    message: string;
    timestamp: string;
  }>;
  errors: string[];
}
