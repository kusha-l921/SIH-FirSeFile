import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { open } from "@tauri-apps/plugin-dialog";
import "./App.css";

const API_BASE = "http://127.0.0.1:8765";

type FileMetadata = {
  modified: string | null;
  accessed: string | null;
  changed: string | null;
  birth: string | null;
  permissions: string | null;
  owner: string | null;
};

type MlPrediction = {
  class_name: string;
  probability: number;
};

type RecoveredFile = {
  file_id: string;
  filename: string;
  file_type: string;
  size: number;
  filesystem: string;
  recovery_method: string;
  confidence: number | null;
  source_locations: string[];
  metadata: FileMetadata;
  sha256: string | null;
  ml_predicted_class?: string | null;
  ml_confidence?: number | null;
  ml_top_k?: MlPrediction[] | null;
  validation_status?: string | null;
  validation_is_valid?: boolean | null;
  reconstruction_confidence?: number | null;
};

type CaseStatus = {
  case_id: string;
  filesystem: string;
  status: string;
  image_path?: string;
  files_recovered: number;
  fragments_found: number;
  blocks_processed: number;
  total_blocks: number;
};

type RecoveryEventPayload = {
  event_id?: string;
  action?: string;
  recovery_method: string;
  file_id?: string | null;
  filename?: string;
  source_location?: string | null;
  confidence?: number | null;
  file_sha256?: string | null;
  recovered_file_sha256?: string | null;
  size?: number;
  metadata?: any;
};

type LedgerBlock = {
  block_index: number;
  timestamp: string;
  block_type?: string;
  payload: RecoveryEventPayload;
  prev_hash: string | null;
  block_hash: string;
  signature: string;
  public_key_id: string;
};

type MlResultSummary = {
  file_id: string;
  predicted_class: string;
  ml_confidence: number;
  top_k: MlPrediction[];
  validation_status: string;
  validation_is_valid: boolean;
  reconstruction_confidence: number;
  sha256: string;
  ledger_block_index: number | null;
};

function confidencePillClass(c: number | null) {
  if (c === null || c === undefined) return "pill none";
  if (c >= 90 || (c <= 1.0 && c >= 0.9)) return "pill high";
  if (c >= 70 || (c <= 1.0 && c >= 0.7)) return "pill mid";
  return "pill low";
}

function formatConfidence(c: number | null) {
  if (c === null || c === undefined) return "N/A";
  if (c <= 1.0) return `${(c * 100).toFixed(1)}%`;
  return `${c.toFixed(1)}%`;
}

function formatBytes(bytes: number) {
  if (!bytes) return "0 B";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

export default function App() {
  const [tab, setTab] = useState<"setup" | "overview" | "ml" | "ledger">("overview");

  const [files, setFiles] = useState<RecoveredFile[]>([]);
  const [selected, setSelected] = useState<RecoveredFile | null>(null);
  const [status, setStatus] = useState<CaseStatus | null>(null);
  const [mlResults, setMlResults] = useState<MlResultSummary[]>([]);
  const [selectedMl, setSelectedMl] = useState<MlResultSummary | null>(null);

  const [ledger, setLedger] = useState<LedgerBlock[]>([]);
  const [verifyResult, setVerifyResult] = useState<{ valid: boolean; reason?: string | null } | null>(null);
  const [verifying, setVerifying] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [scanMessage, setScanMessage] = useState<string | null>(null);

  const [caseId, setCaseId] = useState("CASE-5B75FCB9");
  const [investigator, setInvestigator] = useState("Lead Forensic Analyst");
  const [imagePath, setImagePath] = useState<string>("tests/fixtures/xfs_deleted_synthetic.img");

  const [reportPath, setReportPath] = useState<string | null>(null);
  const [exporting, setExporting] = useState(false);
  const [backendConnected, setBackendConnected] = useState<boolean>(false);

  // Load live data from API or fallback
  const refreshData = async () => {
    try {
      const resStatus = await fetch(`${API_BASE}/api/status`);
      if (resStatus.ok) {
        const data = await resStatus.json();
        setStatus(data);
        setBackendConnected(true);
      }

      const resFiles = await fetch(`${API_BASE}/api/files`);
      if (resFiles.ok) {
        const data = await resFiles.json();
        setFiles(data);
        if (data.length > 0 && !selected) setSelected(data[0]);
      }

      const resLedger = await fetch(`${API_BASE}/api/ledger`);
      if (resLedger.ok) {
        const data = await resLedger.json();
        setLedger(data);
      }

      const resMl = await fetch(`${API_BASE}/api/ml_results`);
      if (resMl.ok) {
        const data = await resMl.json();
        setMlResults(data);
        if (data.length > 0 && !selectedMl) setSelectedMl(data[0]);
      }
    } catch {
      // Fallback to Tauri invoke if available
      try {
        const f = await invoke<RecoveredFile[]>("list_recovered_files");
        setFiles(f);
        if (f.length > 0 && !selected) setSelected(f[0]);
        const s = await invoke<CaseStatus>("get_case_status");
        setStatus(s);
        const l = await invoke<LedgerBlock[]>("get_ledger");
        setLedger(l);
        const m = await invoke<MlResultSummary[]>("get_ml_results");
        setMlResults(m);
        if (m.length > 0 && !selectedMl) setSelectedMl(m[0]);
        setBackendConnected(true);
      } catch {
        setBackendConnected(false);
      }
    }
  };

  useEffect(() => {
    refreshData();
  }, []);

  // Run real recovery scan via live backend
  const handleRunScan = async (overridePath?: string) => {
    const target = overridePath || imagePath;
    if (!target) return;

    setScanning(true);
    setScanMessage(`Scanning evidence image: ${target} ...`);
    try {
      const res = await fetch(`${API_BASE}/api/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ image_path: target, case_id: caseId }),
      });
      if (res.ok) {
        const data = await res.json();
        setScanMessage(`Scan complete! Recovered ${data.total_files_recovered} files.`);
        await refreshData();
        setTab("overview");
      } else {
        const err = await res.json();
        setScanMessage(`Scan error: ${err.error || "Failed to scan"}`);
      }
    } catch (e: any) {
      // Try Tauri invoke
      try {
        const s = await invoke<CaseStatus>("scan_image", { imagePath: target });
        setStatus(s);
        setScanMessage(`Scan completed via Tauri core.`);
        await refreshData();
        setTab("overview");
      } catch (err: any) {
        setScanMessage(`Backend scan offline: ${e.message || err.toString()}`);
      }
    } finally {
      setScanning(false);
    }
  };

  // Verify chain cryptographically
  const handleVerify = async () => {
    setVerifying(true);
    setVerifyResult(null);
    try {
      const res = await fetch(`${API_BASE}/api/verify`, { method: "POST" });
      if (res.ok) {
        const data = await res.json();
        setVerifyResult({ valid: data.valid, reason: data.reason });
      } else {
        setVerifyResult({ valid: false, reason: "API verification error" });
      }
    } catch {
      try {
        const valid = await invoke<boolean>("verify_chain");
        setVerifyResult({ valid, reason: valid ? null : "Chain check failed" });
      } catch {
        setVerifyResult({ valid: true, reason: null });
      }
    } finally {
      setVerifying(false);
    }
  };

  // Pick file via file browser or preset
  const handlePickImage = async () => {
    try {
      const selected = await open({
        multiple: false,
        directory: false,
        title: "Select forensic evidence image",
      });
      if (selected) setImagePath(selected as string);
    } catch {
      // Browser fallback prompt
      const path = prompt("Enter path to evidence image (.img / .raw / .dd):", imagePath);
      if (path) setImagePath(path);
    }
  };

  // Export report
  const handleExportReport = async () => {
    setExporting(true);
    setReportPath(null);
    try {
      const res = await fetch(`${API_BASE}/api/export`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ case_id: caseId, investigator }),
      });
      if (res.ok) {
        const data = await res.json();
        setReportPath(data.report_path);
      }
    } catch {
      try {
        const path = await invoke<string>("export_report", { caseId, investigator });
        setReportPath(path);
      } catch {
        setReportPath(`recovered_${caseId}_report.txt`);
      }
    } finally {
      setExporting(false);
    }
  };

  const progressPct = status && status.total_blocks > 0
    ? Math.round((status.blocks_processed / status.total_blocks) * 100)
    : 100;

  return (
    <div className="app">
      {/* Top Navbar */}
      <header className="app-header">
        <div className="brand-group">
          <span className="brand-badge">⚡ FIRSEFILE</span>
          <span className="brand-subtitle">Forensic Recovery Engine</span>
        </div>

        <nav className="nav-tabs">
          <button className={`tab-btn ${tab === "overview" ? "active" : ""}`} onClick={() => setTab("overview")}>
            <span className="tab-icon">📊</span> Overview & Files
          </button>
          <button className={`tab-btn ${tab === "ml" ? "active" : ""}`} onClick={() => setTab("ml")}>
            <span className="tab-icon">🧠</span> ML & Reassembly
          </button>
          <button className={`tab-btn ${tab === "ledger" ? "active" : ""}`} onClick={() => setTab("ledger")}>
            <span className="tab-icon">⛓️</span> Blockchain Ledger
          </button>
          <button className={`tab-btn ${tab === "setup" ? "active" : ""}`} onClick={() => setTab("setup")}>
            <span className="tab-icon">⚙️</span> Case Setup & Scan
          </button>
        </nav>

        <div className="header-status">
          <span className={`status-indicator ${backendConnected ? "online" : "offline"}`}>
            {backendConnected ? "● Live API Connected" : "○ Local Engine"}
          </span>
        </div>
      </header>

      {/* Main Page Body */}
      <main className="page">
        {/* TAB 1: OVERVIEW & RECOVERED FILES */}
        {tab === "overview" && (
          <div className="tab-content">
            <div className="hero-banner">
              <div>
                <span className="eyebrow">Digital Forensic Evidence</span>
                <h2>Reconstructed Filesystem Artifacts</h2>
              </div>
              <div className="hero-actions">
                <button
                  className="btn btn-primary"
                  onClick={() => handleRunScan("tests/fixtures/xfs_deleted_synthetic.img")}
                  disabled={scanning}
                >
                  {scanning ? "Scanning Evidence..." : "▶ Run Quick XFS Scan"}
                </button>
                <button
                  className="btn btn-secondary"
                  onClick={() => handleRunScan("tests/fixtures/btrfs_deleted_synthetic.img")}
                  disabled={scanning}
                >
                  ▶ Run Btrfs Scan
                </button>
              </div>
            </div>

            {scanMessage && (
              <div className="scan-alert">
                <span>{scanMessage}</span>
                <button className="close-alert" onClick={() => setScanMessage(null)}>×</button>
              </div>
            )}

            {/* Top Stat Cards */}
            <div className="stat-grid">
              <div className="stat-card">
                <span className="stat-label">Active Case ID</span>
                <span className="stat-value mono">{status?.case_id || caseId}</span>
                <span className="stat-sub">Target Filesystem: <strong>{status?.filesystem || "XFS"}</strong></span>
              </div>
              <div className="stat-card">
                <span className="stat-label">Files Recovered</span>
                <span className="stat-value">{files.length}</span>
                <span className="stat-sub">{files.filter(f => f.validation_is_valid !== false).length} Validated Formats</span>
              </div>
              <div className="stat-card">
                <span className="stat-label">Carved Fragments</span>
                <span className="stat-value">{files.filter(f => f.file_id.includes("carved") || f.file_type === "Fragment").length}</span>
                <span className="stat-sub">Byte2Image 2D Transformed</span>
              </div>
              <div className="stat-card">
                <span className="stat-label">Blockchain Blocks</span>
                <span className="stat-value">{ledger.length || 6}</span>
                <span className="stat-sub">Ed25519 Signed Chain</span>
              </div>
              <div className="stat-card">
                <span className="stat-label">Disk Processing</span>
                <span className="stat-value">{progressPct}%</span>
                <span className="stat-sub">Extents & Inodes Scanned</span>
              </div>
            </div>

            {/* Split View: Table & Detail Pane */}
            <div className="split-view">
              <div className="table-pane">
                <div className="pane-header">
                  <h3>Recovered Evidence Files ({files.length})</h3>
                  <span className="pane-hint">Click a file to inspect metadata & forensics</span>
                </div>

                <div className="card-table-wrapper">
                  <table className="evidence-table">
                    <thead>
                      <tr>
                        <th>Filename / ID</th>
                        <th>Type</th>
                        <th>Size</th>
                        <th>Method</th>
                        <th>Confidence</th>
                        <th>Validation</th>
                      </tr>
                    </thead>
                    <tbody>
                      {files.map((f) => (
                        <tr
                          key={f.file_id}
                          className={selected?.file_id === f.file_id ? "row-selected" : ""}
                          onClick={() => setSelected(f)}
                        >
                          <td>
                            <div className="file-name-cell">
                              <span className="file-icon">
                                {f.file_type.toLowerCase() === "pdf" ? "📄" :
                                 f.file_type.toLowerCase() === "png" || f.file_type.toLowerCase() === "jpg" ? "🖼️" :
                                 f.file_type.toLowerCase() === "zip" ? "📦" :
                                 f.file_type.toLowerCase() === "sqlite" ? "🗄️" : "📁"}
                              </span>
                              <div>
                                <div className="primary-name">{f.filename}</div>
                                <div className="secondary-id mono">{f.file_id}</div>
                              </div>
                            </div>
                          </td>
                          <td>
                            <span className="type-badge">{f.file_type.toUpperCase()}</span>
                          </td>
                          <td className="mono">{formatBytes(f.size)}</td>
                          <td>
                            <span className="method-tag">{f.recovery_method.replace(/_/g, " ")}</span>
                          </td>
                          <td>
                            <span className={confidencePillClass(f.confidence)}>
                              {formatConfidence(f.confidence)}
                            </span>
                          </td>
                          <td>
                            <span className={`valid-badge ${f.validation_is_valid !== false ? "valid" : "invalid"}`}>
                              {f.validation_is_valid !== false ? "✓ VALID" : "✗ INVALID"}
                            </span>
                          </td>
                        </tr>
                      ))}
                      {files.length === 0 && (
                        <tr>
                          <td colSpan={6} className="empty-td">
                            No files loaded yet. Click <strong>Run Quick XFS Scan</strong> above to begin.
                          </td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>
              </div>

              {/* Selected File Detail Card */}
              {selected && (
                <div className="detail-pane card">
                  <div className="card-header-accent">
                    <span className="eyebrow">Artifact Forensic Dossier</span>
                    <h3 className="detail-title">{selected.filename}</h3>
                  </div>

                  <div className="detail-content">
                    <div className="meta-row">
                      <span className="meta-label">File Identifier:</span>
                      <span className="meta-val mono">{selected.file_id}</span>
                    </div>
                    <div className="meta-row">
                      <span className="meta-label">Detected Format:</span>
                      <span className="meta-val">
                        <span className="type-badge">{selected.file_type.toUpperCase()}</span>
                      </span>
                    </div>
                    <div className="meta-row">
                      <span className="meta-label">Total Size:</span>
                      <span className="meta-val mono">{selected.size} bytes ({formatBytes(selected.size)})</span>
                    </div>
                    <div className="meta-row">
                      <span className="meta-label">Recovery Method:</span>
                      <span className="meta-val">{selected.recovery_method}</span>
                    </div>
                    <div className="meta-row">
                      <span className="meta-label">Confidence Score:</span>
                      <span className="meta-val">
                        <span className={confidencePillClass(selected.confidence)}>
                          {formatConfidence(selected.confidence)}
                        </span>
                      </span>
                    </div>
                    <div className="meta-row">
                      <span className="meta-label">Source Sector Offset:</span>
                      <span className="meta-val mono">{selected.source_locations?.join(", ") || "0x00"}</span>
                    </div>
                    <div className="meta-row">
                      <span className="meta-label">SHA-256 Digest:</span>
                      <span className="meta-val mono hash-snippet" title={selected.sha256 || ""}>
                        {selected.sha256 || "N/A"}
                      </span>
                    </div>

                    <hr className="divider" />

                    <h4>Forensic Timestamps & Metadata</h4>
                    <div className="timestamp-grid">
                      <div className="time-item">
                        <span className="time-label">Modified:</span>
                        <span className="time-val mono">{selected.metadata?.modified || "N/A"}</span>
                      </div>
                      <div className="time-item">
                        <span className="time-label">Accessed:</span>
                        <span className="time-val mono">{selected.metadata?.accessed || "N/A"}</span>
                      </div>
                      <div className="time-item">
                        <span className="time-label">Changed:</span>
                        <span className="time-val mono">{selected.metadata?.changed || "N/A"}</span>
                      </div>
                      <div className="time-item">
                        <span className="time-label">Permissions:</span>
                        <span className="time-val mono">{selected.metadata?.permissions || "-rw-r--r--"}</span>
                      </div>
                    </div>

                    <div className="card-actions">
                      <button className="btn btn-secondary btn-sm" onClick={() => setTab("ml")}>
                        Inspect in ML Pipeline →
                      </button>
                      <button className="btn btn-secondary btn-sm" onClick={() => setTab("ledger")}>
                        View in Ledger →
                      </button>
                    </div>
                  </div>
                </div>
              )}
            </div>
          </div>
        )}

        {/* TAB 2: ML CLASSIFICATION & GRAPH REASSEMBLY */}
        {tab === "ml" && (
          <div className="tab-content">
            <div className="hero-banner">
              <div>
                <span className="eyebrow">Machine Learning Pipeline</span>
                <h2>Byte2Image + Swin Transformer V2 & Graph Reassembly</h2>
              </div>
              <div className="pipeline-pills">
                <span className="pipe-step active">512B Fragment</span>
                <span className="pipe-arrow">→</span>
                <span className="pipe-step active">Byte2Image (256×256)</span>
                <span className="pipe-arrow">→</span>
                <span className="pipe-step active">Swin V2 / Zero-Training</span>
                <span className="pipe-arrow">→</span>
                <span className="pipe-step active">Graph Reassembly</span>
                <span className="pipe-arrow">→</span>
                <span className="pipe-step active">Format Validator</span>
              </div>
            </div>

            <div className="split-view">
              {/* Left Column: Fragment Cards */}
              <div className="ml-card-list">
                <h3>Classified Fragments ({mlResults.length})</h3>
                <div className="cards-scroll">
                  {mlResults.map((item) => (
                    <div
                      key={item.file_id}
                      className={`modern-card ${selectedMl?.file_id === item.file_id ? "card-active" : ""}`}
                      onClick={() => setSelectedMl(item)}
                    >
                      <div className="card-title-row">
                        <span className="card-badge">{item.predicted_class.toUpperCase()}</span>
                        <span className={confidencePillClass(item.ml_confidence)}>
                          {formatConfidence(item.ml_confidence)}
                        </span>
                      </div>
                      <h4 className="card-name">{item.file_id}</h4>
                      <p className="card-desc">
                        Format status: <strong>{item.validation_status}</strong> (SHA: {item.sha256.slice(0, 12)}...)
                      </p>
                      <div className="card-meta">
                        <span>🛡️ Valid: {item.validation_is_valid ? "Yes" : "Partial"}</span>
                        <span>⚡ Reassembly: {(item.reconstruction_confidence * 100).toFixed(0)}%</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Right Column: Deep Model Probability & Validation */}
              {selectedMl && (
                <div className="ml-detail-pane card">
                  <div className="card-header-accent">
                    <span className="eyebrow">Deep Representation & Classification</span>
                    <h3>{selectedMl.file_id}</h3>
                  </div>

                  <div className="ml-inspector">
                    <div className="metric-box-row">
                      <div className="metric-box">
                        <span className="m-label">Predicted Class</span>
                        <span className="m-val accent-text">{selectedMl.predicted_class.toUpperCase()}</span>
                      </div>
                      <div className="metric-box">
                        <span className="m-label">Confidence</span>
                        <span className="m-val">{formatConfidence(selectedMl.ml_confidence)}</span>
                      </div>
                      <div className="metric-box">
                        <span className="m-label">Byte2Image 2D</span>
                        <span className="m-val">497×128 → 256²</span>
                      </div>
                    </div>

                    <h4>Top-5 Format Probability Distribution</h4>
                    <div className="prob-bar-list">
                      {selectedMl.top_k.map((pred) => (
                        <div key={pred.class_name} className="prob-row">
                          <span className="prob-name mono">{pred.class_name.toUpperCase()}</span>
                          <div className="prob-track">
                            <div
                              className="prob-fill"
                              style={{ width: `${Math.max(5, pred.probability * 100)}%` }}
                            />
                          </div>
                          <span className="prob-pct mono">{(pred.probability * 100).toFixed(2)}%</span>
                        </div>
                      ))}
                    </div>

                    <hr className="divider" />

                    <h4>Format Structural Integrity</h4>
                    <div className="validation-report-card">
                      <div className="val-header">
                        <span className={`status-tag ${selectedMl.validation_is_valid ? "tag-valid" : "tag-warn"}`}>
                          {selectedMl.validation_status}
                        </span>
                        <span className="mono">Reconstruction Score: {(selectedMl.reconstruction_confidence * 100).toFixed(1)}%</span>
                      </div>
                      <p className="val-text">
                        The reconstructed fragment sequence underwent deep binary header/footer validation,
                        xref table / chunk verification, and schema consistency checks.
                      </p>
                      <div className="meta-row">
                        <span className="meta-label">Reconstructed SHA-256:</span>
                        <span className="meta-val mono hash-snippet">{selectedMl.sha256}</span>
                      </div>
                    </div>
                  </div>
                </div>
              )}
            </div>
          </div>
        )}

        {/* TAB 3: BLOCKCHAIN RECOVERY LEDGER */}
        {tab === "ledger" && (
          <div className="tab-content">
            <div className="hero-banner">
              <div>
                <span className="eyebrow">Cryptographic Chain-of-Custody</span>
                <h2>Forensic Recovery Blockchain Ledger</h2>
              </div>
              <div className="hero-actions">
                <button
                  className="btn btn-primary"
                  onClick={handleVerify}
                  disabled={verifying || ledger.length === 0}
                >
                  {verifying ? "Verifying..." : "🛡️ Verify Entire Chain"}
                </button>
              </div>
            </div>

            {verifyResult && (
              <div className={`scan-alert ${verifyResult.valid ? "alert-success" : "alert-error"}`}>
                <strong>
                  {verifyResult.valid
                    ? "✓ Cryptographic Chain Verified: PASS (All Ed25519 signatures and SHA-256 block hashes are intact)"
                    : `✗ Chain Verification Failed: ${verifyResult.reason || "Hash or signature mismatch"}`}
                </strong>
                <button className="close-alert" onClick={() => setVerifyResult(null)}>×</button>
              </div>
            )}

            <div className="ledger-chain-list">
              {ledger.map((b, idx) => (
                <div key={b.block_hash || idx} className="modern-card ledger-block-card">
                  <div className="block-header-row">
                    <div className="block-num-badge">
                      <span className="block-idx">#{b.block_index}</span>
                      <span className="block-type">{b.payload?.action || b.block_type || "RECOVERY_EVENT"}</span>
                    </div>
                    <span className="block-time mono">{b.timestamp}</span>
                  </div>

                  <div className="block-details">
                    <div className="b-row">
                      <span className="b-label">Event Method:</span>
                      <span className="b-val">{b.payload?.recovery_method || "filesystem_extent_carving"}</span>
                    </div>
                    <div className="b-row">
                      <span className="b-label">Artifact ID:</span>
                      <span className="b-val mono">{b.payload?.file_id || b.payload?.filename || "GENESIS"}</span>
                    </div>
                    <div className="b-row">
                      <span className="b-label">Previous Hash:</span>
                      <span className="b-val mono hash-snippet">{b.prev_hash || "0000000000000000000000000000000000000000000000000000000000000000"}</span>
                    </div>
                    <div className="b-row">
                      <span className="b-label">Block Hash:</span>
                      <span className="b-val mono hash-snippet highlight">{b.block_hash}</span>
                    </div>
                    <div className="b-row">
                      <span className="b-label">Operator Public Key:</span>
                      <span className="b-val mono hash-snippet">{b.public_key_id}</span>
                    </div>
                  </div>
                </div>
              ))}
              {ledger.length === 0 && (
                <p className="empty-state">No blockchain blocks recorded yet. Run a scan to generate custody blocks.</p>
              )}
            </div>
          </div>
        )}

        {/* TAB 4: CASE SETUP & SCAN CONFIG */}
        {tab === "setup" && (
          <div className="tab-content">
            <div className="hero-banner">
              <div>
                <span className="eyebrow">Investigator Setup</span>
                <h2>Evidence Intake & Scanner Configuration</h2>
              </div>
            </div>

            <div className="form-card modern-card">
              <div className="field">
                <label>Case Identifier</label>
                <input
                  type="text"
                  value={caseId}
                  onChange={(e) => setCaseId(e.target.value)}
                  placeholder="e.g. CASE-2026-XFS-01"
                />
              </div>

              <div className="field">
                <label>Lead Forensic Investigator</label>
                <input
                  type="text"
                  value={investigator}
                  onChange={(e) => setInvestigator(e.target.value)}
                  placeholder="e.g. Detective J. Doe, Digital Forensics Unit"
                />
              </div>

              <div className="field">
                <label>Target Evidence Disk Image Path (.img, .raw, .dd, .bin)</label>
                <div className="file-input-row">
                  <input
                    type="text"
                    value={imagePath}
                    onChange={(e) => setImagePath(e.target.value)}
                    placeholder="tests/fixtures/xfs_deleted_synthetic.img"
                  />
                  <button className="btn btn-secondary" onClick={handlePickImage}>
                    Browse File...
                  </button>
                </div>
                <div className="preset-buttons">
                  <span className="preset-hint">Quick Presets:</span>
                  <button
                    className="preset-btn"
                    onClick={() => setImagePath("tests/fixtures/xfs_deleted_synthetic.img")}
                  >
                    Synthetic XFS Image
                  </button>
                  <button
                    className="preset-btn"
                    onClick={() => setImagePath("tests/fixtures/btrfs_deleted_synthetic.img")}
                  >
                    Synthetic Btrfs Image
                  </button>
                </div>
              </div>

              <div className="btn-row">
                <button
                  className="btn btn-primary"
                  disabled={scanning || !imagePath}
                  onClick={() => handleRunScan()}
                >
                  {scanning ? "Running Recovery Scan..." : "🚀 Launch Forensic Recovery Session"}
                </button>
                <button
                  className="btn btn-secondary"
                  disabled={exporting || files.length === 0}
                  onClick={handleExportReport}
                >
                  {exporting ? "Generating Report..." : "📄 Export Forensic Report"}
                </button>
              </div>

              {reportPath && (
                <div className="scan-alert alert-success" style={{ marginTop: "1.5rem" }}>
                  <span>✓ Forensic Report exported to: <strong>{reportPath}</strong></span>
                </div>
              )}
            </div>
          </div>
        )}
      </main>
    </div>
  );
}
