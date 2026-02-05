import { useEffect, useMemo, useState } from 'react';

type Overview = any;
type BlockSummary = { number: number; txCount: number; dataHash: string | null; previousHash: string | null; channelId: string | null };
type TxSummary = { txid: string; chaincodeName: string | null; functionName: string | null; timestamp: string | null; validationCode: string | null; blockNumber: number };
type TxDetail = {
  txid: string;
  blockNumber: number;
  timestamp: string | null;
  validationCode: string | null;
  creatorMspId: { value: string | null; reason?: string };
  chaincodeName: { value: string | null; reason?: string };
  functionName: { value: string | null; reason?: string };
  rwSetSummary: { value: string | null; reason?: string };
  endorsements: { value: string[] | null; reason?: string };
  raw: Record<string, unknown>;
};

type NavKey =
  | 'overview'
  | 'explorer-blocks'
  | 'explorer-transactions'
  | 'explorer-search'
  | 'chaincode-definition'
  | 'chaincode-invocations'
  | 'audit-exports';

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
  const [nav, setNav] = useState<NavKey>('overview');
  const [adminPass, setAdminPass] = useState('');
  const [logs, setLogs] = useState('');
  const [selectedService, setSelectedService] = useState('lognotary-ccaas');

  const [blocks, setBlocks] = useState<BlockSummary[]>([]);
  const [blocksLoading, setBlocksLoading] = useState(false);
  const [blocksError, setBlocksError] = useState('');
  const [blockFilter, setBlockFilter] = useState('');
  const [selectedBlock, setSelectedBlock] = useState<number | null>(null);
  const [selectedBlockDetail, setSelectedBlockDetail] = useState<any | null>(null);

  const [invocations, setInvocations] = useState<TxSummary[]>([]);
  const [definition, setDefinition] = useState<any>(null);

  const [searchInput, setSearchInput] = useState('');
  const [txDetail, setTxDetail] = useState<TxDetail | null>(null);
  const [searchError, setSearchError] = useState('');
  const [exportBundle, setExportBundle] = useState<any>(null);
  const [showRaw, setShowRaw] = useState(false);

  const refreshOverview = async () => {
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

  const loadBlocks = async () => {
    setBlocksLoading(true);
    setBlocksError('');
    try {
      const data = await api<{ blocks: BlockSummary[] }>('/api/v1/explorer/blocks?channel=soclogs&limit=20');
      setBlocks(data.blocks ?? []);
    } catch (e) {
      setBlocksError((e as Error).message);
    } finally {
      setBlocksLoading(false);
    }
  };

  const loadDefinitionAndInvocations = async () => {
    try {
      const [def, inv] = await Promise.all([
        api('/api/v1/chaincode/definition?channel=soclogs&name=lognotary'),
        api<{ invocations: TxSummary[] }>('/api/v1/chaincode/invocations?channel=soclogs&name=lognotary&limit=50')
      ]);
      setDefinition(def);
      setInvocations(inv.invocations ?? []);
    } catch {
      // best effort
    }
  };

  useEffect(() => {
    refreshOverview();
    loadBlocks();
    loadDefinitionAndInvocations();
    const id = setInterval(refreshOverview, 8000);
    return () => clearInterval(id);
  }, []);

  const blockSummary = useMemo(() => {
    if (!overview?.summary?.blockHeights) return '-';
    return Object.entries(overview.summary.blockHeights)
      .map(([peer, height]) => `${peer}: ${height ?? 'N/A'}`)
      .join(' | ');
  }, [overview]);

  const filteredBlocks = useMemo(() => {
    if (!blockFilter) return blocks;
    return blocks.filter((b) => String(b.number).includes(blockFilter));
  }, [blockFilter, blocks]);

  const txList = useMemo(() => blocks.flatMap((b) => (b as any).transactions ?? []), [blocks]);

  const fetchBlockDetail = async (blockNumber: number) => {
    const data = await api(`/api/v1/explorer/blocks/${blockNumber}?channel=soclogs`);
    setSelectedBlock(blockNumber);
    setSelectedBlockDetail(data);
    setNav('explorer-transactions');
  };

  const fetchTxDetail = async (txid: string) => {
    setSearchError('');
    try {
      const data = await api<TxDetail>(`/api/v1/explorer/tx/${encodeURIComponent(txid)}?channel=soclogs`);
      setTxDetail(data);
      setNav('explorer-search');
    } catch (e) {
      setTxDetail(null);
      setSearchError((e as Error).message);
    }
  };

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
    refreshOverview();
  };

  const copyText = async (value: string) => navigator.clipboard.writeText(value);

  const exportCurrent = async () => {
    if (txDetail) {
      const data = await api(`/api/v1/audit/export/tx/${encodeURIComponent(txDetail.txid)}?channel=soclogs`);
      setExportBundle(data);
      setNav('audit-exports');
      return;
    }
    if (selectedBlock !== null) {
      const data = await api(`/api/v1/audit/export/block/${selectedBlock}?channel=soclogs`);
      setExportBundle(data);
      setNav('audit-exports');
    }
  };

  if (loading) return <div className="center">Initializing Fabric SOC Console...</div>;

  return (
    <div className="shell">
      <aside className="sidebar">
        <h1>Fabric Explorer</h1>
        <NavGroup title="Overview" items={[{ key: 'overview', label: 'Overview' }]} nav={nav} onPick={setNav} />
        <NavGroup
          title="Explorer"
          items={[
            { key: 'explorer-blocks', label: 'Blocks' },
            { key: 'explorer-transactions', label: 'Transactions' },
            { key: 'explorer-search', label: 'Search' }
          ]}
          nav={nav}
          onPick={setNav}
        />
        <NavGroup
          title="Chaincode"
          items={[
            { key: 'chaincode-definition', label: 'Definition' },
            { key: 'chaincode-invocations', label: 'Invocations' }
          ]}
          nav={nav}
          onPick={setNav}
        />
        <NavGroup title="Audit" items={[{ key: 'audit-exports', label: 'Exports' }]} nav={nav} onPick={setNav} />
      </aside>

      <main className="content">
        <header className="topbar">
          <div className="topbar-meta">
            <span>Network: {overview?.network}</span>
            <span>Channels: {(overview?.channels || []).join(', ')}</span>
            <span className={statusClass(overview?.overallStatus)}>{overview?.overallStatus}</span>
            <span>Refreshed: {new Date(overview?.lastRefreshTime).toLocaleTimeString()}</span>
          </div>
        </header>

        {error && <div className="error">{error}</div>}

        {nav === 'overview' && (
          <>
            <section className="grid cards">
              <Card title="Peers" value={`${overview?.summary.peersUp}/${overview?.summary.peersUp + overview?.summary.peersDown} up`} />
              <Card title="Orderer" value={`${overview?.summary.ordererUp}/${overview?.summary.ordererUp + overview?.summary.ordererDown} up`} />
              <Card title="Channels" value={String(overview?.summary.channelsCount)} />
              <Card title="Chaincodes" value={String(overview?.summary.chaincodesCount)} />
              <Card title="CCaaS Reachable" value={overview?.summary.ccaaSReachable ? 'YES' : 'NO'} />
              <Card title="Peer Heights" value={blockSummary} />
            </section>

            <section className="grid two-col">
              <Panel title="Organizations">
                <table>
                  <thead><tr><th>Org</th><th>MSP ID</th><th>Peers</th><th>Status</th></tr></thead>
                  <tbody>
                    {overview?.organizations?.map((org: any) => (
                      <tr key={org.name}><td>{org.name}</td><td>{org.mspId}</td><td>{org.peers.join(', ')}</td><td><span className={statusClass(org.status)}>{org.status}</span></td></tr>
                    ))}
                  </tbody>
                </table>
              </Panel>

              <Panel title="Chaincode · lognotary">
                <ul className="kv">
                  <li><b>Name</b><span>{overview?.chaincode?.name}</span></li>
                  <li><b>Version</b><span>{overview?.chaincode?.version ?? '-'}</span></li>
                  <li><b>Sequence</b><span>{overview?.chaincode?.sequence ?? '-'}</span></li>
                  <li><b>Package ID</b><span>{overview?.chaincode?.packageId ?? '-'}</span></li>
                  <li><b>Endpoint</b><span>{overview?.chaincode?.endpoint}</span></li>
                  <li><b>Ready</b><span className={overview?.chaincode?.readyForEndorsements ? 'ok' : 'bad'}>{overview?.chaincode?.readyForEndorsements ? 'TRUE' : 'FALSE'}</span></li>
                </ul>
              </Panel>
            </section>

            <Panel title="Services">
              <table>
                <thead><tr><th>Name</th><th>Status</th><th>Uptime</th><th>Network</th><th>Ports</th><th>IP</th></tr></thead>
                <tbody>
                  {overview?.services?.map((svc: any) => (
                    <tr key={svc.name}><td>{svc.name}</td><td>{svc.status}</td><td>{svc.uptime}</td><td>{svc.network}</td><td>{svc.ports || '-'}</td><td>{svc.ip}</td></tr>
                  ))}
                </tbody>
              </table>
            </Panel>
          </>
        )}

        {nav === 'explorer-blocks' && (
          <Panel title="Blocks Explorer">
            <div className="toolbar">
              <input placeholder="Filter by block number" value={blockFilter} onChange={(e) => setBlockFilter(e.target.value)} />
              <button onClick={loadBlocks}>Refresh</button>
            </div>
            {blocksLoading ? <p>Loading blocks...</p> : blocksError ? <p className="error">{blocksError}</p> : (
              <table>
                <thead><tr><th>Block</th><th>Tx Count</th><th>Data Hash</th><th>Previous Hash</th><th></th></tr></thead>
                <tbody>
                  {filteredBlocks.length ? filteredBlocks.map((b) => (
                    <tr key={b.number}>
                      <td>{b.number}</td><td>{b.txCount}</td><td className="mono">{b.dataHash ?? '-'}</td><td className="mono">{b.previousHash ?? '-'}</td>
                      <td><button onClick={() => fetchBlockDetail(b.number)}>View</button></td>
                    </tr>
                  )) : <tr><td colSpan={5}>No blocks found.</td></tr>}
                </tbody>
              </table>
            )}
          </Panel>
        )}

        {nav === 'explorer-transactions' && (
          <Panel title={`Transaction Detail Viewer${selectedBlock !== null ? ` · Block ${selectedBlock}` : ''}`}>
            {!selectedBlockDetail ? <p>Select a block from Blocks Explorer to load transactions.</p> : (
              <table>
                <thead><tr><th>TxID</th><th>Chaincode</th><th>Function</th><th>Timestamp</th><th></th></tr></thead>
                <tbody>
                  {(selectedBlockDetail.transactions ?? []).map((tx: TxSummary) => (
                    <tr key={tx.txid}>
                      <td className="mono">{tx.txid}</td>
                      <td>{tx.chaincodeName ?? '-'}</td>
                      <td>{tx.functionName ?? '-'}</td>
                      <td>{tx.timestamp ? new Date(tx.timestamp).toLocaleString() : '-'}</td>
                      <td><button onClick={() => fetchTxDetail(tx.txid)}>Forensic View</button></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </Panel>
        )}

        {nav === 'explorer-search' && (
          <Panel title="Search by Block Number / TxID">
            <div className="toolbar">
              <input placeholder="TxID or block number" value={searchInput} onChange={(e) => setSearchInput(e.target.value)} />
              <button onClick={() => {
                if (/^\d+$/.test(searchInput)) fetchBlockDetail(Number(searchInput));
                else fetchTxDetail(searchInput);
              }}>Search</button>
              <button onClick={exportCurrent}>Export verification bundle</button>
            </div>
            {searchError && <div className="error">{searchError}</div>}
            {txDetail && (
              <div className="forensic">
                <h3>Summary</h3>
                <ul className="kv">
                  <li><b>TxID</b><span className="mono">{txDetail.txid}</span></li>
                  <li><b>Block Number</b><span>{txDetail.blockNumber}</span></li>
                  <li><b>Timestamp</b><span>{txDetail.timestamp ? new Date(txDetail.timestamp).toLocaleString() : '-'}</span></li>
                  <li><b>Validation</b><span>{txDetail.validationCode ?? '-'}</span></li>
                </ul>
                <div className="row">
                  <button onClick={() => copyText(txDetail.txid)}>Copy TxID</button>
                  {selectedBlockDetail?.header?.dataHash && <button onClick={() => copyText(selectedBlockDetail.header.dataHash)}>Copy Block Hash</button>}
                </div>
                <h3>Endorsements / Creator Org (best-effort)</h3>
                <p>{txDetail.creatorMspId.value ?? txDetail.creatorMspId.reason}</p>
                <h3>Chaincode</h3>
                <p>{txDetail.chaincodeName.value ?? txDetail.chaincodeName.reason} · {txDetail.functionName.value ?? txDetail.functionName.reason}</p>
                <h3>RW Set Summary</h3>
                <p>{txDetail.rwSetSummary.value ?? txDetail.rwSetSummary.reason}</p>
                <button onClick={() => setShowRaw((v) => !v)}>{showRaw ? 'Hide' : 'View'} raw JSON</button>
                {showRaw && <pre>{JSON.stringify(txDetail.raw, null, 2)}</pre>}
              </div>
            )}
          </Panel>
        )}

        {nav === 'chaincode-definition' && (
          <Panel title="Chaincode Definition">
            {!definition ? <p>Loading...</p> : <ul className="kv">
              <li><b>Name</b><span>{definition.name}</span></li>
              <li><b>Channel</b><span>{definition.channel}</span></li>
              <li><b>Version</b><span>{definition.version ?? '-'}</span></li>
              <li><b>Sequence</b><span>{definition.sequence ?? '-'}</span></li>
              <li><b>Init Required</b><span>{definition.initRequired ?? '-'}</span></li>
            </ul>}
          </Panel>
        )}

        {nav === 'chaincode-invocations' && (
          <Panel title="Invocation History · lognotary">
            <table>
              <thead><tr><th>TxID</th><th>Block</th><th>Function</th><th>Timestamp</th><th></th></tr></thead>
              <tbody>
                {invocations.length ? invocations.map((tx) => (
                  <tr key={tx.txid}>
                    <td className="mono">{tx.txid}</td>
                    <td>{tx.blockNumber}</td>
                    <td>{tx.functionName ?? '-'}</td>
                    <td>{tx.timestamp ? new Date(tx.timestamp).toLocaleString() : '-'}</td>
                    <td><button onClick={() => fetchTxDetail(tx.txid)}>View</button></td>
                  </tr>
                )) : <tr><td colSpan={5}>No invocation data available.</td></tr>}
              </tbody>
            </table>
          </Panel>
        )}

        {nav === 'audit-exports' && (
          <Panel title="Audit Exports">
            {!exportBundle ? <p>No export generated yet. Use search/transaction screens to export.</p> : (
              <>
                <div className="row"><button onClick={() => copyText(JSON.stringify(exportBundle))}>Copy bundle</button></div>
                <pre>{JSON.stringify(exportBundle, null, 2)}</pre>
              </>
            )}
          </Panel>
        )}

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
      </main>
    </div>
  );
}

function Card({ title, value }: { title: string; value: string }) {
  return <div className="card"><h3>{title}</h3><p>{value}</p></div>;
}

function Panel({ title, children }: { title: string; children: any }) {
  return <div className="panel"><h2>{title}</h2>{children}</div>;
}

function NavGroup({ title, items, nav, onPick }: { title: string; items: Array<{ key: NavKey; label: string }>; nav: NavKey; onPick: (key: NavKey) => void }) {
  return (
    <div className="nav-group">
      <p>{title}</p>
      {items.map((item) => (
        <button key={item.key} className={`nav-item ${nav === item.key ? 'active' : ''}`} onClick={() => onPick(item.key)}>{item.label}</button>
      ))}
    </div>
  );
}
