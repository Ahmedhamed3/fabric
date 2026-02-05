import { config, requiredServices } from '../config.js';
import { ChaincodeStatus, Overview, ServiceContainerStatus } from '../types/index.js';
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

  async getContainers(): Promise<ServiceContainerStatus[]> {
    const out = await runCommand(
      'docker',
      ['ps', '-a', '--format', '{{json .}}'],
      12000
    );

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
