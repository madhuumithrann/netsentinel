import React, { useState } from 'react';
import { createRoot } from 'react-dom/client';
import { Shield, Upload, Activity, AlertTriangle, FileSearch, Network, CheckCircle2 } from 'lucide-react';
import './style.css';

function App() {
  const [file, setFile] = useState(null), [result, setResult] = useState(null), [busy, setBusy] = useState(false), [error, setError] = useState('');
  async function analyze() {
    if (!file) return;
    setBusy(true); setError(''); setResult(null);
    const body = new FormData(); body.append('file', file);
    try { const response = await fetch('http://localhost:8000/api/analyze', { method: 'POST', body }); const data = await response.json(); if (!response.ok) throw new Error(data.detail || 'Analysis failed'); setResult(data); }
    catch (e) { setError(e.message + '. Check that the backend is running on port 8000.'); }
    finally { setBusy(false); }
  }
  return <div className="app"><aside className="sidebar"><div className="brand"><div className="brand-icon"><Shield size={22}/></div><div><b>NetSentinel</b><small>NETWORK INTELLIGENCE</small></div></div><div className="nav active"><Activity size={17}/> Overview</div><div className="nav"><AlertTriangle size={17}/> Incidents</div><div className="nav"><Network size={17}/> Traffic analysis</div><div className="side-note"><Shield size={18}/><b>Offline-first analysis</b><span>PCAP files are analyzed locally by your backend. No live network capture.</span></div></aside>
  <main><header><div><span className="eyebrow">SECURITY OPERATIONS / OVERVIEW</span><h1>Network diagnosis</h1><p>Understand faults and threats hidden in packet captures.</p></div><div className="status"><i/> ANALYSIS ENGINE READY</div></header>
  <section className="upload panel"><div className="upload-icon"><Upload size={23}/></div><div className="upload-copy"><h2>Analyze a packet capture</h2><p>Upload a .pcap or .pcapng file · Maximum 100 MB</p><input type="file" accept=".pcap,.pcapng" onChange={e=>{setFile(e.target.files[0]);setResult(null);setError('')}}/></div><button disabled={!file || busy} onClick={analyze}>{busy ? 'Analyzing…' : 'Analyze capture'} <FileSearch size={16}/></button></section>
  {error && <div className="error">{error}</div>}
  {!result && <section className="empty panel"><div className="empty-icon"><FileSearch size={30}/></div><h2>Waiting for a capture</h2><p>Upload a packet capture to inspect traffic, identify suspicious patterns and generate evidence-backed findings.</p><div className="empty-points"><span><CheckCircle2/> Custom detection rules</span><span><CheckCircle2/> Packet-level evidence</span><span><CheckCircle2/> Plain-language guidance</span></div></section>}
  {result && <><section className="metrics"><Metric label="Packets analyzed" value={result.packets_analyzed}/><Metric label="Incidents" value={result.summary.incident_count}/><Metric label="High severity" value={result.summary.high}/><Metric label="Duration" value={`${result.duration_seconds}s`}/></section><section className="panel results"><div className="section-head"><div><span className="eyebrow">ANALYSIS REPORT</span><h2>{result.file}</h2></div><span className="tag">COMPLETE</span></div><p className="muted">{result.notice}</p><h3>Detected incidents</h3>{result.incidents.length===0?<div className="clean">No configured detection rules were triggered in this capture. This does not guarantee the network is safe.</div>:result.incidents.map(item=><article className="incident" key={item.id}><div className="incident-top"><span className={'severity '+item.severity.toLowerCase()}>{item.severity}</span><b>{item.title}</b><small>{item.id}</small></div><p>{item.summary}</p><div className="detail"><b>Likely cause</b><span>{item.likely_cause}</span></div><div className="detail"><b>Recommended action</b><span>{item.recommendation}</span></div><div className="evidence">Evidence packets: {item.evidence_packets.join(', ') || 'Not available'} · Confidence: {item.confidence}</div></article>)}</section><section className="panel"><h3>Protocol distribution</h3><div className="protocols">{Object.entries(result.protocols).map(([k,v])=><div key={k}><b>{k}</b><strong>{v}</strong></div>)}</div></section></>}
  <footer>NETSENTINEL · HACKATHON BUILD · FINDINGS REQUIRE HUMAN VERIFICATION</footer></main></div>;
}
function Metric({label,value}) { return <div className="metric panel"><span>{label}</span><strong>{value}</strong></div> }

createRoot(document.getElementById('root')).render(<App/>);
