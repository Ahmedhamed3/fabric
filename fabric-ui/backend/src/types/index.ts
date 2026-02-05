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

export interface FieldAvailability<T> {
  value: T | null;
  reason?: string;
}

export interface ExplorerBlockSummary {
  number: number;
  txCount: number;
  dataHash: string | null;
  previousHash: string | null;
  channelId: string | null;
}

export interface ExplorerTransactionSummary {
  txid: string;
  chaincodeName: string | null;
  functionName: string | null;
  timestamp: string | null;
  validationCode: string | null;
  blockNumber: number;
}

export interface ExplorerBlocksResponse {
  channel: string;
  from: number;
  limit: number;
  blocks: ExplorerBlockSummary[];
  warnings: string[];
}

export interface ExplorerTransactionDetail {
  txid: string;
  blockNumber: number;
  timestamp: string | null;
  validationCode: string | null;
  creatorMspId: FieldAvailability<string>;
  chaincodeName: FieldAvailability<string>;
  functionName: FieldAvailability<string>;
  rwSetSummary: FieldAvailability<string>;
  endorsements: FieldAvailability<string[]>;
  raw: Record<string, unknown>;
}

export interface ExplorerBlockDetail {
  number: number;
  channel: string;
  txCount: number;
  header: {
    dataHash: string | null;
    previousHash: string | null;
  };
  transactions: ExplorerTransactionSummary[];
  raw: Record<string, unknown>;
}

export interface ChaincodeDefinitionResponse {
  channel: string;
  name: string;
  version: string | null;
  sequence: string | null;
  endorsementPolicy: string | null;
  initRequired: string | null;
  collectionsConfig: string | null;
}

export interface ChaincodeInvocationsResponse {
  channel: string;
  name: string;
  limit: number;
  invocations: ExplorerTransactionSummary[];
  warnings: string[];
}

export interface AuditExportResponse {
  type: 'block' | 'transaction';
  generatedAt: string;
  channel: string;
  payload: Record<string, unknown>;
}
