import { config, requiredServices } from '../config.js';
import {
  AuditExportResponse,
  ChaincodeDefinitionResponse,
  ChaincodeInvocationsResponse,
  ChaincodeStatus,
  ExplorerBlockDetail,
  ExplorerBlocksResponse,
  ExplorerTransactionDetail,
  ExplorerTransactionSummary,
  Overview,
  ServiceContainerStatus
} from '../types/index.js';
import { runCommand } from '../utils/exec.js';

type Snapshot = {
  containers: Record<string, string>;
  ccaaSReachable: boolean;
  blockHeights: Record<string, number | null>;
};

export class FabricService {
  private events: Array<{ type: string; message: string; timestamp: string }> = [];
  private previous: Snapshot | null = null;

  async ensureNetworkStarted(): Promise<void> {
    await runCommand('bash', [config.startScript, 'up'], 240000);
  }

  private recordEvent(type: string, message: string): void {
    this.events.unshift({ type, message, timestamp: new Date().toISOString() });
    this.events = this.events.slice(0, 10);
  }

  private runPeerCmd(envScript: string, cmd: string, timeout = 15000) {
    const full = `source ${envScript} && export PATH=/opt/fabric-dev/bin:$PATH && ${cmd}`;
    return runCommand('bash', ['-lc', full], timeout, config.socnetDir);
  }

  private decodeBlockFromPeerOutput(stdout: string): Record<string, any> | null {
    const trimmed = stdout.trim();
    if (!trimmed) return null;

    const lines = trimmed.split('\n').map((line) => line.trim());
    const jsonStartIdx = lines.findIndex((line) => line.startsWith('{'));
    if (jsonStartIdx < 0) return null;

    const candidate = lines.slice(jsonStartIdx).join('\n');
    try {
      return JSON.parse(candidate);
    } catch {
      return null;
    }
  }

  private getBlockTxSummaries(blockJson: Record<string, any>, blockNumber: number): ExplorerTransactionSummary[] {
    const dataItems: any[] = blockJson?.data?.data ?? [];
    return dataItems
      .map((item) => {
        const payload = item?.payload?.data;
        const chHeader = payload?.header?.channel_header ?? {};
        const actions = payload?.data?.actions ?? [];
        const spec = actions?.[0]?.payload?.chaincode_proposal_payload?.input?.chaincode_spec ?? {};
        const args: string[] = spec?.input?.args ?? [];

        return {
          txid: chHeader.tx_id ?? 'unknown',
          chaincodeName: spec?.chaincode_id?.name ?? null,
          functionName: args?.[0] ?? null,
          timestamp: chHeader.timestamp ?? null,
          validationCode: payload?.metadata?.[2] ?? null,
          blockNumber
        } as ExplorerTransactionSummary;
      })
      .filter((tx) => tx.txid !== 'unknown');
  }

  private async fetchBlockJson(channel: string, number: number): Promise<{ block: Record<string, any> | null; warning?: string }> {
    const cmd = [
      'tmp=$(mktemp)',
      `peer channel fetch ${number} "$tmp" -c ${channel} -o localhost:7050 --tls --cafile "$ORDERER_CA" 2>/dev/null`,
      'if [ $? -ne 0 ]; then rm -f "$tmp"; exit 2; fi',
      'configtxlator proto_decode --input "$tmp" --type common.Block',
      'rcode=$?',
      'rm -f "$tmp"',
      'exit $rcode'
    ].join(' && ');

    const out = await this.runPeerCmd(`${config.composeDir}/env_org1.sh`, cmd, 20000);
    if (out.exitCode !== 0) {
      return { block: null, warning: `Unable to fetch/decode block ${number}.` };
    }

    const parsed = this.decodeBlockFromPeerOutput(out.stdout);
    if (!parsed) {
      return { block: null, warning: `Unable to parse JSON for block ${number}.` };
    }

    return { block: parsed };
  }

  async getContainers(): Promise<ServiceContainerStatus[]> {
    const out = await runCommand('docker', ['ps', '-a', '--format', '{{json .}}'], 12000);

    if (out.exitCode !== 0) {
      return [];
    }

    const rows = out.stdout
      .split('\n')
      .map((line) => line.trim())
      .filter(Boolean)
      .map((line) => JSON.parse(line) as { Names: string; Status: string; RunningFor: string; Networks: string; Ports: string });

    const target = rows.filter((r) => requiredServices.includes(r.Names));

    const details = await Promise.all(
      target.map(async (container) => {
        const inspect = await runCommand(
          'docker',
          ['inspect', container.Names, '--format', '{{range $k,$v := .NetworkSettings.Networks}}{{$k}} {{$v.IPAddress}}{{end}}'],
          9000
        );
        const [network, ip] = inspect.stdout.trim().split(' ');
        return {
          name: container.Names,
          status: container.Status,
          uptime: container.RunningFor,
          network: network ?? container.Networks,
          ports: container.Ports ?? '-',
          ip: ip ?? '-',
          running: container.Status.toLowerCase().startsWith('up')
        };
      })
    );

    return details;
  }

  async getChannels(): Promise<string[]> {
    const result = await this.runPeerCmd(`${config.composeDir}/env_org1.sh`, 'peer channel list', 12000);
    if (result.exitCode !== 0) {
      return [config.channel];
    }
    return result.stdout
      .split('\n')
      .map((s) => s.trim())
      .filter((s) => s && !s.includes('Channels peers has joined') && !s.startsWith('202'));
  }

  async getBlockHeights(): Promise<Record<string, number | null>> {
    const commands = [
      { peer: 'peer0.org1.example.com', env: `${config.composeDir}/env_org1.sh` },
      { peer: 'peer0.org2.example.com', env: `${config.composeDir}/env_org2.sh` }
    ];
    const output: Record<string, number | null> = {};

    for (const item of commands) {
      const res = await this.runPeerCmd(item.env, `peer channel getinfo -c ${config.channel}`, 14000);
      const match = res.stdout.match(/Block height:\s*(\d+)/i);
      output[item.peer] = match ? Number(match[1]) : null;
    }

    return output;
  }

  async getChaincode(): Promise<ChaincodeStatus> {
    const errors: string[] = [];
    const committed = await this.runPeerCmd(
      `${config.composeDir}/env_org1.sh`,
      `peer lifecycle chaincode querycommitted -C ${config.channel} -n ${config.ccName}`,
      14000
    );
    const installed = await this.runPeerCmd(`${config.composeDir}/env_org1.sh`, 'peer lifecycle chaincode queryinstalled', 14000);
    const dns = await runCommand('docker', ['exec', 'peer0.org1.example.com', 'getent', 'hosts', config.ccContainer], 8000);
    const ccContainer = await runCommand('docker', ['inspect', '-f', '{{.State.Running}}', config.ccContainer], 7000);

    if (committed.exitCode !== 0) errors.push('querycommitted failed');
    if (installed.exitCode !== 0) errors.push('queryinstalled failed');

    const sequence = committed.stdout.match(/Sequence:\s*(\d+)/)?.[1] ?? null;
    const version = committed.stdout.match(/Version:\s*([^,\n]+)/)?.[1]?.trim() ?? null;
    const initRequired = committed.stdout.match(/Init required:\s*(\w+)/i)?.[1] ?? null;

    const packageId = installed.stdout
      .split('\n')
      .find((line) => line.includes(`Label: ${config.ccLabel}`))
      ?.match(/Package ID:\s*([^,]+)/)?.[1]
      ?.trim() ?? null;

    const ccaaSReachable = dns.exitCode === 0 && dns.stdout.trim().length > 0 && ccContainer.stdout.trim() === 'true';

    return {
      name: config.ccName,
      version,
      sequence,
      initRequired,
      packageId,
      endpoint: config.ccEndpoint,
      ccaaSReachable,
      readyForEndorsements: ccaaSReachable,
      errors
    };
  }

  async getExplorerBlocks(channel: string, limit = 20, from?: number): Promise<ExplorerBlocksResponse> {
    const warnings: string[] = [];
    const heightRes = await this.runPeerCmd(`${config.composeDir}/env_org1.sh`, `peer channel getinfo -c ${channel}`, 15000);
    const heightMatch = heightRes.stdout.match(/Block height:\s*(\d+)/i);
    if (!heightMatch) {
      return { channel, from: 0, limit, blocks: [], warnings: ['Unable to read channel height.'] };
    }

    const height = Number(heightMatch[1]);
    const start = typeof from === 'number' ? from : Math.max(height - 1, 0);
    const blocks = [];

    for (let i = start; i >= 0 && blocks.length < limit; i -= 1) {
      const fetched = await this.fetchBlockJson(channel, i);
      if (fetched.warning) {
        warnings.push(fetched.warning);
        continue;
      }

      const block = fetched.block;
      if (!block) continue;
      const txs = this.getBlockTxSummaries(block, i);
      blocks.push({
        number: i,
        txCount: txs.length,
        dataHash: block?.header?.data_hash ?? null,
        previousHash: block?.header?.previous_hash ?? null,
        channelId: block?.data?.data?.[0]?.payload?.header?.channel_header?.channel_id ?? channel
      });
    }

    return { channel, from: start, limit, blocks, warnings };
  }

  async getExplorerBlockDetail(channel: string, number: number): Promise<ExplorerBlockDetail> {
    const fetched = await this.fetchBlockJson(channel, number);
    if (!fetched.block) throw new Error(fetched.warning ?? `Block ${number} unavailable`);

    const transactions = this.getBlockTxSummaries(fetched.block, number);
    return {
      number,
      channel,
      txCount: transactions.length,
      header: {
        dataHash: fetched.block?.header?.data_hash ?? null,
        previousHash: fetched.block?.header?.previous_hash ?? null
      },
      transactions,
      raw: fetched.block
    };
  }

  async getTransactionDetail(channel: string, txid: string): Promise<ExplorerTransactionDetail> {
    const blocks = await this.getExplorerBlocks(channel, 120);
    for (const block of blocks.blocks) {
      const detail = await this.getExplorerBlockDetail(channel, block.number);
      const tx = detail.transactions.find((item) => item.txid === txid);
      if (tx) {
        return {
          txid,
          blockNumber: block.number,
          timestamp: tx.timestamp,
          validationCode: tx.validationCode,
          creatorMspId: { value: null, reason: 'Creator MSP parsing is not available via current CLI decode path.' },
          chaincodeName: {
            value: tx.chaincodeName,
            reason: tx.chaincodeName ? undefined : 'Chaincode was not discoverable from decoded payload.'
          },
          functionName: {
            value: tx.functionName,
            reason: tx.functionName ? undefined : 'Function name was not discoverable from decoded payload.'
          },
          rwSetSummary: { value: null, reason: 'RW set decode not implemented yet.' },
          endorsements: { value: null, reason: 'Endorsement extraction is not available via current CLI decode path.' },
          raw: detail.raw
        };
      }
    }

    throw new Error(`Transaction ${txid} not found in recent block window.`);
  }

  async getChaincodeDefinition(channel: string, name: string): Promise<ChaincodeDefinitionResponse> {
    const cmd = `peer lifecycle chaincode querycommitted -C ${channel} -n ${name}`;
    const out = await this.runPeerCmd(`${config.composeDir}/env_org1.sh`, cmd, 14000);
    if (out.exitCode !== 0) throw new Error('Unable to query committed chaincode definition.');

    return {
      channel,
      name,
      version: out.stdout.match(/Version:\s*([^,\n]+)/)?.[1]?.trim() ?? null,
      sequence: out.stdout.match(/Sequence:\s*(\d+)/)?.[1] ?? null,
      endorsementPolicy: out.stdout.match(/Endorsement Plugin:\s*([^,\n]+)/)?.[1]?.trim() ?? null,
      initRequired: out.stdout.match(/Init required:\s*(\w+)/i)?.[1] ?? null,
      collectionsConfig: out.stdout.match(/Collections:\s*([^\n]+)/)?.[1]?.trim() ?? null
    };
  }

  async getChaincodeInvocations(channel: string, name: string, limit = 50): Promise<ChaincodeInvocationsResponse> {
    const warnings: string[] = [];
    const blocks = await this.getExplorerBlocks(channel, 120);
    const invocations: ExplorerTransactionSummary[] = [];

    for (const block of blocks.blocks) {
      const detail = await this.getExplorerBlockDetail(channel, block.number);
      for (const tx of detail.transactions) {
        if (tx.chaincodeName === name) {
          invocations.push(tx);
        }
        if (invocations.length >= limit) {
          return { channel, name, limit, invocations, warnings: [...warnings, ...blocks.warnings] };
        }
      }
    }

    if (!invocations.length) warnings.push('No matching invocations found in scanned block window.');
    return { channel, name, limit, invocations, warnings: [...warnings, ...blocks.warnings] };
  }

  async exportBlockBundle(channel: string, number: number): Promise<AuditExportResponse> {
    const detail = await this.getExplorerBlockDetail(channel, number);
    return {
      type: 'block',
      generatedAt: new Date().toISOString(),
      channel,
      payload: {
        blockNumber: detail.number,
        txCount: detail.txCount,
        dataHash: detail.header.dataHash,
        previousHash: detail.header.previousHash,
        txids: detail.transactions.map((tx) => tx.txid),
        timestamps: detail.transactions.map((tx) => tx.timestamp)
      }
    };
  }

  async exportTxBundle(channel: string, txid: string): Promise<AuditExportResponse> {
    const detail = await this.getTransactionDetail(channel, txid);
    return {
      type: 'transaction',
      generatedAt: new Date().toISOString(),
      channel,
      payload: {
        txid: detail.txid,
        blockNumber: detail.blockNumber,
        timestamp: detail.timestamp,
        validationCode: detail.validationCode,
        creatorMspId: detail.creatorMspId.value,
        chaincodeName: detail.chaincodeName.value,
        functionName: detail.functionName.value,
        rwSetSummary: detail.rwSetSummary.value,
        endorsements: detail.endorsements.value
      }
    };
  }

  async getOverview(): Promise<Overview> {
    const [services, channels, chaincode, blockHeights] = await Promise.all([
      this.getContainers(),
      this.getChannels(),
      this.getChaincode(),
      this.getBlockHeights()
    ]);

    const errors: string[] = [];
    if (services.length < requiredServices.length) errors.push('One or more required services are missing.');
    if (!chaincode.ccaaSReachable) errors.push('CCaaS reachability check failed.');

    const peers = services.filter((s) => s.name.includes('peer0.'));
    const orderers = services.filter((s) => s.name.includes('orderer'));

    const overview: Overview = {
      network: 'socnet',
      channels,
      overallStatus: errors.length === 0 ? 'Healthy' : 'Degraded',
      lastRefreshTime: new Date().toISOString(),
      summary: {
        peersUp: peers.filter((s) => s.running).length,
        peersDown: peers.filter((s) => !s.running).length,
        ordererUp: orderers.filter((s) => s.running).length,
        ordererDown: orderers.filter((s) => !s.running).length,
        channelsCount: channels.length,
        chaincodesCount: chaincode.name ? 1 : 0,
        ccaaSReachable: chaincode.ccaaSReachable,
        blockHeights
      },
      organizations: [
        {
          name: 'Org1',
          mspId: 'Org1MSP',
          peers: ['peer0.org1.example.com'],
          status: services.find((s) => s.name === 'peer0.org1.example.com')?.running ? 'Healthy' : 'Degraded'
        },
        {
          name: 'Org2',
          mspId: 'Org2MSP',
          peers: ['peer0.org2.example.com'],
          status: services.find((s) => s.name === 'peer0.org2.example.com')?.running ? 'Healthy' : 'Degraded'
        }
      ],
      services,
      chaincode,
      latestEvents: this.events,
      errors
    };

    this.updateEvents(overview);
    return { ...overview, latestEvents: this.events };
  }

  private updateEvents(overview: Overview): void {
    const current: Snapshot = {
      containers: Object.fromEntries(overview.services.map((s) => [s.name, s.status])),
      ccaaSReachable: overview.chaincode.ccaaSReachable,
      blockHeights: overview.summary.blockHeights
    };

    if (!this.previous) {
      this.previous = current;
      this.recordEvent('startup', 'Fabric UI telemetry initialized.');
      return;
    }

    for (const [name, status] of Object.entries(current.containers)) {
      if (this.previous.containers[name] && this.previous.containers[name] !== status) {
        this.recordEvent('container', `${name} changed status: ${this.previous.containers[name]} -> ${status}`);
      }
    }

    if (this.previous.ccaaSReachable !== current.ccaaSReachable) {
      this.recordEvent('ccaas', `CCaaS reachability changed to ${current.ccaaSReachable ? 'reachable' : 'unreachable'}`);
    }

    for (const [peer, height] of Object.entries(current.blockHeights)) {
      const prev = this.previous.blockHeights[peer];
      if (typeof prev === 'number' && typeof height === 'number' && prev !== height) {
        this.recordEvent('block', `${peer} block height changed: ${prev} -> ${height}`);
      }
    }

    this.previous = current;
  }

  async restartService(service: string): Promise<{ ok: boolean; message: string }> {
    const coreServices = ['orderer.example.com', 'peer0.org1.example.com', 'peer0.org2.example.com'];
    if (coreServices.includes(service) && !config.allowCoreRestart) {
      return { ok: false, message: 'Core service restarts are disabled. Set ALLOW_CORE_RESTART=true.' };
    }
    if (!requiredServices.includes(service)) {
      return { ok: false, message: 'Service is not in the approved restart list.' };
    }

    const result = await runCommand('docker', ['restart', service], 20000);
    return {
      ok: result.exitCode === 0,
      message: result.exitCode === 0 ? `${service} restarted successfully.` : result.stderr || 'Restart failed.'
    };
  }

  async getLogs(service: string, tail: number): Promise<{ ok: boolean; output: string }> {
    if (!requiredServices.includes(service)) {
      return { ok: false, output: 'Service is not in the approved log list.' };
    }

    const result = await runCommand('docker', ['logs', service, '--tail', String(tail)], 12000);
    return {
      ok: result.exitCode === 0,
      output: `${result.stdout}${result.stderr}`
    };
  }
}
