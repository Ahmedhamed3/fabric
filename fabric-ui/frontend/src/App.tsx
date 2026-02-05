import { useEffect, useMemo, useState } from 'react';

type Overview = any;

const statusClass = (status: string) => (status === 'Healthy' ? 'pill healthy' : 'pill degraded');

async function api<T>(url: string, init?: RequestInit): Promise<T> {
  const res = await fetch(url, init);
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

export function App() {
  const [overview, setOverview] = useState<Overview | null>(null);
  const [error, setError] = useState<string>('');
  const [loading, setLoading] = useState(true);
  const [adminPass, setAdminPass] = useState('');
  const [logs, setLogs] = useState('');
  const [selectedService, setSelectedService] = useState('lognotary-ccaas');

  const refresh = async () => {
    try {
      const data = await api<Overview>('/api/status/overview');
      setOverview(data);
      setError('');
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    refresh();
    const id = setInterval(refresh, 8000);
    return () => clearInterval(id);
  }, []);

  const blockSummary = useMemo(() => {
    if (!overview?.summary?.blockHeights) return '-';
    return Object.entries(overview.summary.blockHeights)
      .map(([peer, height]) => `${peer}: ${height ?? 'N/A'}`)
      .join(' | ');
  }, [overview]);

  const fetchLogs = async () => {
    const q = new URLSearchParams({ service: selectedService, tail: '200' });
    const data = await api<{ output: string }>(`/api/admin/logs?${q}`, {
      headers: { 'x-admin-password': adminPass }
    });
    setLogs(data.output || '(empty)');
  };

  const restart = async () => {
    const risky = selectedService.includes('peer0') || selectedService.includes('orderer');
    if (risky && !confirm(`Restart ${selectedService}? This can impact endorsements.`)) return;
    const data = await api<{ message: string }>('/api/admin/restart', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-admin-password': adminPass },
      body: JSON.stringify({ service: selectedService })
    });
    alert(data.message);
    refresh();
  };

  if (loading) return <div className="center">Initializing Fabric SOC Console...</div>;

  return (
    <div className="app">
      <header className="topbar">
        <h1>Fabric UI Console · Network Overview</h1>
        <div className="topbar-meta">
          <span>Network: {overview?.network}</span>
          <span>Channels: {(overview?.channels || []).join(', ')}</span>
          <span className={statusClass(overview?.overallStatus)}>{overview?.overallStatus}</span>
          <span>Refreshed: {new Date(overview?.lastRefreshTime).toLocaleTimeString()}</span>
        </div>
      </header>

      {error && <div className="error">{error}</div>}

      <section className="grid cards">
        <Card title="Peers" value={`${overview?.summary.peersUp}/${overview?.summary.peersUp + overview?.summary.peersDown} up`} icon="🖧" />
        <Card title="Orderer" value={`${overview?.summary.ordererUp}/${overview?.summary.ordererUp + overview?.summary.ordererDown} up`} icon="🛡" />
        <Card title="Channels" value={String(overview?.summary.channelsCount)} icon="⛓" />
        <Card title="Chaincodes" value={String(overview?.summary.chaincodesCount)} icon="📦" />
        <Card title="CCaaS Reachable" value={overview?.summary.ccaaSReachable ? 'YES' : 'NO'} icon="🛰" />
        <Card title="Latest Block Heights" value={blockSummary} icon="📈" />
      </section>

      <section className="grid two-col">
        <Panel title="Organizations">
          <table><thead><tr><th>Org</th><th>MSP ID</th><th>Peers</th><th>Status</th></tr></thead><tbody>
            {overview?.organizations?.map((org: any) => (
              <tr key={org.name}><td>{org.name}</td><td>{org.mspId}</td><td>{org.peers.join(', ')}</td><td><span className={statusClass(org.status)}>{org.status}</span></td></tr>
            ))}
          </tbody></table>
        </Panel>

        <Panel title="Chaincode · lognotary">
          <ul className="kv">
            <li><b>Name</b><span>{overview?.chaincode?.name}</span></li>
            <li><b>Version</b><span>{overview?.chaincode?.version ?? '-'}</span></li>
            <li><b>Sequence</b><span>{overview?.chaincode?.sequence ?? '-'}</span></li>
            <li><b>Init Required</b><span>{overview?.chaincode?.initRequired ?? '-'}</span></li>
            <li><b>Package ID</b><span>{overview?.chaincode?.packageId ?? '-'}</span></li>
            <li><b>CCaaS Endpoint</b><span>{overview?.chaincode?.endpoint}</span></li>
            <li><b>Ready for endorsements</b><span className={overview?.chaincode?.readyForEndorsements ? 'ok' : 'bad'}>{overview?.chaincode?.readyForEndorsements ? 'TRUE' : 'FALSE'}</span></li>
          </ul>
        </Panel>
      </section>

      <section className="panel">
        <h2>Services</h2>
        <table><thead><tr><th>Name</th><th>Status</th><th>Uptime</th><th>Network</th><th>Ports</th><th>IP</th></tr></thead><tbody>
          {overview?.services?.map((svc: any) => (
            <tr key={svc.name}><td>{svc.name}</td><td>{svc.status}</td><td>{svc.uptime}</td><td>{svc.network}</td><td>{svc.ports || '-'}</td><td>{svc.ip}</td></tr>
          ))}
        </tbody></table>
      </section>

      <section className="grid two-col">
        <Panel title="Latest Events">
          <ul className="feed">
            {(overview?.latestEvents || []).map((evt: any, idx: number) => (
              <li key={idx}><span>{new Date(evt.timestamp).toLocaleTimeString()}</span> <b>{evt.type}</b> {evt.message}</li>
            ))}
          </ul>
        </Panel>
        <Panel title="Admin Actions (Guarded)">
          <div className="admin">
            <input value={adminPass} onChange={(e) => setAdminPass(e.target.value)} type="password" placeholder="Admin password" />
            <select value={selectedService} onChange={(e) => setSelectedService(e.target.value)}>
              {overview?.services?.map((svc: any) => <option key={svc.name}>{svc.name}</option>)}
            </select>
            <div className="row"><button onClick={fetchLogs}>View logs (tail 200)</button><button onClick={restart}>Restart service</button></div>
            <pre>{logs || 'No logs loaded.'}</pre>
          </div>
        </Panel>
      </section>
    </div>
  );
}

function Card({ title, value, icon }: { title: string; value: string; icon: string }) {
  return <div className="card"><h3>{icon} {title}</h3><p>{value}</p></div>;
}

function Panel({ title, children }: { title: string; children: any }) {
  return <div className="panel"><h2>{title}</h2>{children}</div>;
}
