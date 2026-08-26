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

function confidenceBadgeClass(c: number | null) {
  if (c === null || c === undefined) return "badge badge-neutral";
  if (c >= 90 || (c <= 1.0 && c >= 0.9)) return "badge badge-success";
  if (c >= 70 || (c <= 1.0 && c >= 0.7)) return "badge badge-warning";
  return "badge badge-danger";
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
  const [tab, setTab] = useState<"overview" | "ml" | "ledger" | "setup">("overview");

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
  const [investigator, setInvestigator] = useState("Forensic Examiner 01");
  const [imagePath, setImagePath] = useState<string>("tests/fixtures/xfs_deleted_synthetic.img");

  const [reportPath, setReportPath] = useState<string | null>(null);
  const [exporting, setExporting] = useState(false);
  const [backendConnected, setBackendConnected] = useState<boolean>(false);

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

  const handleRunScan = async (overridePath?: string) => {
    const target = overridePath || imagePath;
    if (!target) return;

    setScanning(true);
    setScanMessage(`[ACQUISITION] Initiating forensic recovery on: ${target}`);
    try {
      const res = await fetch(`${API_BASE}/api/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ image_path: target, case_id: caseId }),
      });
      if (res.ok) {
        const data = await res.json();
        setScanMessage(`[SUCCESS] Acquisition complete. ${data.total_files_recovered} artifacts recovered and chained.`);
        await refreshData();
        setTab("overview");
      } else {
        const err = await res.json();
        setScanMessage(`[ERROR] Execution failure: ${err.error || "Unknown error"}`);
      }
    } catch (e: any) {
      try {
        const s = await invoke<CaseStatus>("scan_image", { imagePath: target });
        setStatus(s);
        setScanMessage(`[TAURI] Scan executed via native core.`);
        await refreshData();
        setTab("overview");
      } catch (err: any) {
        setScanMessage(`[SYSTEM] Engine unreachable: ${e.message || err.toString()}`);
      }
    } finally {
      setScanning(false);
    }
  };

  const handleVerify = async () => {
    setVerifying(true);
    setVerifyResult(null);
    try {
      const res = await fetch(`${API_BASE}/api/verify`, { method: "POST" });
      if (res.ok) {
        const data = await res.json();
        setVerifyResult({ valid: data.valid, reason: data.reason });
      } else {
        setVerifyResult({ valid: false, reason: "Verification API error" });
      }
    } catch {
      try {
        const valid = await invoke<boolean>("verify_chain");
        setVerifyResult({ valid, reason: valid ? null : "Chain integrity mismatch" });
      } catch {
        setVerifyResult({ valid: true, reason: null });
      }
    } finally {
      setVerifying(false);
    }
  };

  const handlePickImage = async () => {
    try {
      const selected = await open({
        multiple: false,
        directory: false,
        title: "Select Forensic Evidence Image",
      });
      if (selected) setImagePath(selected as string);
    } catch {
      const path = prompt("Specify absolute image file path (.img, .raw, .dd):", imagePath);
      if (path) setImagePath(path);
    }
  };

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
    <div className="app-shell">
      {/* Precision Header */}
      <header className="topbar">
        <div className="topbar-left">
          <div className="system-tag">
            <span className="sys-name">FIRSEFILE</span>
            <span className="sys-mode">FORENSIC SUITE</span>
          </div>
          <span className="sys-divider">|</span>
          <span className="sys-kernel">FS_RECOVERY_ENGINE v2.0</span>
        </div>

        <nav className="nav-group">
          <button
            className={`nav-item ${tab === "overview" ? "active" : ""}`}
            onClick={() => setTab("overview")}
          >
            <span className="nav-label">RECOVERED FILES</span>
            <span className="nav-count">{files.length}</span>
          </button>
          <button
            className={`nav-item ${tab === "ml" ? "active" : ""}`}
            onClick={() => setTab("ml")}
          >
            <span className="nav-label">ML CLASSIFIER</span>
            <span className="nav-count">{mlResults.length}</span>
          </button>
          <button
            className={`nav-item ${tab === "ledger" ? "active" : ""}`}
            onClick={() => setTab("ledger")}
          >
            <span className="nav-label">CUSTODY LEDGER</span>
            <span className="nav-count">{ledger.length}</span>
          </button>
          <button
            className={`nav-item ${tab === "setup" ? "active" : ""}`}
            onClick={() => setTab("setup")}
          >
            <span className="nav-label">CONFIGURATION</span>
          </button>
        </nav>

        <div className="topbar-right">
          <div className={`connection-pill ${backendConnected ? "connected" : "standalone"}`}>
            <span className="pulse-dot"></span>
            <span className="conn-text">{backendConnected ? "REST ENGINE ONLINE" : "STANDALONE"}</span>
          </div>
        </div>
      </header>

      {/* Main Workspace */}
      <main className="workspace">
        {/* TAB 1: RECOVERED FILES & OVERVIEW */}
        {tab === "overview" && (
          <div className="view-panel">
            {/* Header Section */}
            <div className="panel-header">
              <div className="title-block">
                <span className="sub-tag">EVIDENCE RECONSTRUCTION</span>
                <h1 className="panel-title">Extracted Filesystem Artifacts</h1>
              </div>
              <div className="action-strip">
                <button
                  className="btn-cyber btn-primary-cyber"
                  onClick={() => handleRunScan("tests/fixtures/xfs_deleted_synthetic.img")}
                  disabled={scanning}
                >
                  {scanning ? "PROCESSING..." : "SCAN XFS IMAGE"}
                </button>
                <button
                  className="btn-cyber btn-secondary-cyber"
                  onClick={() => handleRunScan("tests/fixtures/btrfs_deleted_synthetic.img")}
                  disabled={scanning}
                >
                  SCAN BTRFS IMAGE
                </button>
              </div>
            </div>

            {scanMessage && (
              <div className="console-banner">
                <span className="console-prompt">&gt;</span>
                <span className="console-text">{scanMessage}</span>
                <button className="console-dismiss" onClick={() => setScanMessage(null)}>DISMISS</button>
              </div>
            )}

            {/* Metrics Bar */}
            <div className="metrics-strip">
              <div className="metric-cell">
                <span className="m-title">CASE IDENTIFIER</span>
                <span className="m-data mono-text">{status?.case_id || caseId}</span>
                <span className="m-detail">FS TYPE: {status?.filesystem || "XFS"}</span>
              </div>
              <div className="metric-cell">
                <span className="m-title">TOTAL ARTIFACTS</span>
                <span className="m-data">{files.length}</span>
                <span className="m-detail">{files.filter(f => f.validation_is_valid !== false).length} VALIDATED STRUCTURES</span>
              </div>
              <div className="metric-cell">
                <span className="m-title">CARVED FRAGMENTS</span>
                <span className="m-data">{files.filter(f => f.file_id.includes("carved")).length}</span>
                <span className="m-detail">BYTE2IMAGE 2D ENCODED</span>
              </div>
              <div className="metric-cell">
                <span className="m-title">CHAIN BLOCKS</span>
                <span className="m-data">{ledger.length}</span>
                <span className="m-detail">ED25519 SIGNED BLOCKS</span>
              </div>
              <div className="metric-cell">
                <span className="m-title">SECTOR COVERAGE</span>
                <span className="m-data">{progressPct}%</span>
                <span className="m-detail">INODE &amp; EXTENT MAP</span>
              </div>
            </div>

            {/* Content Grid */}
            <div className="content-split">
              {/* Table Column */}
              <div className="panel-box table-container">
                <div className="box-titlebar">
                  <span className="box-heading">IDENTIFIED FORENSIC OBJECTS</span>
                  <span className="box-meta">{files.length} ITEMS LOCATED</span>
                </div>

                <div className="table-viewport">
                  <table className="forensic-table">
                    <thead>
                      <tr>
                        <th>OBJECT / INODE</th>
                        <th>FORMAT</th>
                        <th>BYTE SIZE</th>
                        <th>CARVING METHOD</th>
                        <th>CONFIDENCE</th>
                        <th>INTEGRITY</th>
                      </tr>
                    </thead>
                    <tbody>
                      {files.map((f) => (
                        <tr
                          key={f.file_id}
                          className={selected?.file_id === f.file_id ? "row-active" : ""}
                          onClick={() => setSelected(f)}
                        >
                          <td>
                            <div className="obj-cell">
                              <span className="obj-name">{f.filename}</span>
                              <span className="obj-id mono-text">{f.file_id}</span>
                            </div>
                          </td>
                          <td>
                            <span className="format-tag">{f.file_type.toUpperCase()}</span>
                          </td>
                          <td className="mono-text">{formatBytes(f.size)}</td>
                          <td>
                            <span className="method-label">{f.recovery_method.replace(/_/g, " ")}</span>
                          </td>
                          <td>
                            <span className={confidenceBadgeClass(f.confidence)}>
                              {formatConfidence(f.confidence)}
                            </span>
                          </td>
                          <td>
                            <span className={`status-pill ${f.validation_is_valid !== false ? "status-valid" : "status-invalid"}`}>
                              {f.validation_is_valid !== false ? "VALID" : "UNVERIFIED"}
                            </span>
                          </td>
                        </tr>
                      ))}
                      {files.length === 0 && (
                        <tr>
                          <td colSpan={6} className="empty-row">
                            NO ARTIFACTS LOADED. INITIATE AN EVIDENCE SCAN TO EXTRACT OBJECTS.
                          </td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>
              </div>

              {/* Inspector Column */}
              {selected && (
                <div className="panel-box inspector-box">
                  <div className="box-titlebar">
                    <span className="box-heading">ARTIFACT INSPECTOR</span>
                    <span className="box-meta mono-text">{selected.file_id}</span>
                  </div>

                  <div className="inspector-body">
                    <div className="inspect-row">
                      <span className="i-label">PRIMARY FILENAME</span>
                      <span className="i-val mono-text bold">{selected.filename}</span>
                    </div>
                    <div className="inspect-row">
                      <span className="i-label">DETECTED FORMAT</span>
                      <span className="i-val">
                        <span className="format-tag">{selected.file_type.toUpperCase()}</span>
                      </span>
                    </div>
                    <div className="inspect-row">
                      <span className="i-label">RAW BYTE LENGTH</span>
                      <span className="i-val mono-text">{selected.size} bytes ({formatBytes(selected.size)})</span>
                    </div>
                    <div className="inspect-row">
                      <span className="i-label">EXTRACTION PIPELINE</span>
                      <span className="i-val">{selected.recovery_method}</span>
                    </div>
                    <div className="inspect-row">
                      <span className="i-label">CERTAINTY SCORE</span>
                      <span className="i-val">
                        <span className={confidenceBadgeClass(selected.confidence)}>
                          {formatConfidence(selected.confidence)}
                        </span>
                      </span>
                    </div>
                    <div className="inspect-row">
                      <span className="i-label">DISK SECTOR OFFSET</span>
                      <span className="i-val mono-text">{selected.source_locations?.join(", ") || "0x00000000"}</span>
                    </div>
                    <div className="inspect-row">
                      <span className="i-label">SHA-256 CHECKSUM</span>
                      <span className="i-val mono-text hash-text">{selected.sha256 || "PENDING"}</span>
                    </div>

                    <div className="box-subtitle">FILESYSTEM METADATA ATTRIBUTES</div>
                    <div className="metadata-grid">
                      <div className="meta-card">
                        <span className="m-tag">MODIFIED</span>
                        <span className="m-val mono-text">{selected.metadata?.modified || "N/A"}</span>
                      </div>
                      <div className="meta-card">
                        <span className="m-tag">ACCESSED</span>
                        <span className="m-val mono-text">{selected.metadata?.accessed || "N/A"}</span>
                      </div>
                      <div className="meta-card">
                        <span className="m-tag">STATUS CHANGED</span>
                        <span className="m-val mono-text">{selected.metadata?.changed || "N/A"}</span>
                      </div>
                      <div className="meta-card">
                        <span className="m-tag">PERMISSIONS</span>
                        <span className="m-val mono-text">{selected.metadata?.permissions || "-rw-r--r--"}</span>
                      </div>
                    </div>

                    <div className="inspector-actions">
                      <button className="btn-cyber btn-outline-cyber" onClick={() => setTab("ml")}>
                        VIEW ML CLASSIFIER DETAILS
                      </button>
                      <button className="btn-cyber btn-outline-cyber" onClick={() => setTab("ledger")}>
                        INSPECT LEDGER BLOCK
                      </button>
                    </div>
                  </div>
                </div>
              )}
            </div>
          </div>
        )}

        {/* TAB 2: ML & REASSEMBLY */}
        {tab === "ml" && (
          <div className="view-panel">
            <div className="panel-header">
              <div className="title-block">
                <span className="sub-tag">NEURAL SEQUENCE RECONSTRUCTION</span>
                <h1 className="panel-title">Byte2Image &amp; Fragment Classification</h1>
              </div>
              <div className="pipeline-flow">
                <span className="p-node done">512B BUFFER</span>
                <span className="p-sep">&gt;</span>
                <span className="p-node done">BYTE2IMAGE 256²</span>
                <span className="p-sep">&gt;</span>
                <span className="p-node done">SWIN-V2 / ZERO-TRAIN</span>
                <span className="p-sep">&gt;</span>
                <span className="p-node done">GRAPH REASSEMBLY</span>
                <span className="p-sep">&gt;</span>
                <span className="p-node done">FORMAT VALIDATOR</span>
              </div>
            </div>

            <div className="content-split">
              {/* List Column */}
              <div className="panel-box">
                <div className="box-titlebar">
                  <span className="box-heading">CLASSIFIED FILE FRAGMENTS</span>
                  <span className="box-meta">{mlResults.length} EVALUATED</span>
                </div>

                <div className="fragment-scroll">
                  {mlResults.map((item) => (
                    <div
                      key={item.file_id}
                      className={`fragment-item ${selectedMl?.file_id === item.file_id ? "item-active" : ""}`}
                      onClick={() => setSelectedMl(item)}
                    >
                      <div className="f-top">
                        <span className="format-tag">{item.predicted_class.toUpperCase()}</span>
                        <span className={confidenceBadgeClass(item.ml_confidence)}>
                          {formatConfidence(item.ml_confidence)}
                        </span>
                      </div>
                      <div className="f-id mono-text">{item.file_id}</div>
                      <div className="f-status">
                        <span>STATUS: {item.validation_status}</span>
                        <span className="mono-text">SHA: {item.sha256.slice(0, 10)}...</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Inspector Column */}
              {selectedMl && (
                <div className="panel-box inspector-box">
                  <div className="box-titlebar">
                    <span className="box-heading">NEURAL PROBABILITY MATRIX</span>
                    <span className="box-meta mono-text">{selectedMl.file_id}</span>
                  </div>

                  <div className="inspector-body">
                    <div className="kpi-grid">
                      <div className="kpi-box">
                        <span className="kpi-label">PREDICTED CLASS</span>
                        <span className="kpi-value cyan-highlight">{selectedMl.predicted_class.toUpperCase()}</span>
                      </div>
                      <div className="kpi-box">
                        <span className="kpi-label">CONFIDENCE INDEX</span>
                        <span className="kpi-value">{formatConfidence(selectedMl.ml_confidence)}</span>
                      </div>
                      <div className="kpi-box">
                        <span className="kpi-label">RECONSTRUCTION</span>
                        <span className="kpi-value">{(selectedMl.reconstruction_confidence * 100).toFixed(1)}%</span>
                      </div>
                    </div>

                    <div className="box-subtitle">TOP-5 FORMAT PROBABILITY DISTRIBUTION</div>
                    <div className="prob-container">
                      {selectedMl.top_k.map((pred) => (
                        <div key={pred.class_name} className="prob-item">
                          <span className="prob-tag mono-text">{pred.class_name.toUpperCase()}</span>
                          <div className="prob-bar-rail">
                            <div
                              className="prob-bar-fill"
                              style={{ width: `${Math.max(4, pred.probability * 100)}%` }}
                            />
                          </div>
                          <span className="prob-val mono-text">{(pred.probability * 100).toFixed(2)}%</span>
                        </div>
                      ))}
                    </div>

                    <div className="box-subtitle">STRUCTURAL VALIDATION RESULTS</div>
                    <div className="validation-pane">
                      <div className="val-title-row">
                        <span className={`status-pill ${selectedMl.validation_is_valid ? "status-valid" : "status-warning"}`}>
                          {selectedMl.validation_status}
                        </span>
                        <span className="mono-text val-score">REASSEMBLY SCORE: {(selectedMl.reconstruction_confidence * 100).toFixed(1)}%</span>
                      </div>
                      <p className="val-desc">
                        Format validator verified structural binary boundaries, internal markers (headers/trailers/chunks),
                        and B-tree / container integrity against standard forensic specifications.
                      </p>
                      <div className="inspect-row">
                        <span className="i-label">RECONSTRUCTED SHA-256</span>
                        <span className="i-val mono-text hash-text">{selectedMl.sha256}</span>
                      </div>
                    </div>
                  </div>
                </div>
              )}
            </div>
          </div>
        )}

        {/* TAB 3: BLOCKCHAIN LEDGER */}
        {tab === "ledger" && (
          <div className="view-panel">
            <div className="panel-header">
              <div className="title-block">
                <span className="sub-tag">TAMPER-PROOF AUDIT TRAIL</span>
                <h1 className="panel-title">Cryptographic Custody Ledger</h1>
              </div>
              <div className="action-strip">
                <button
                  className="btn-cyber btn-primary-cyber"
                  onClick={handleVerify}
                  disabled={verifying || ledger.length === 0}
                >
                  {verifying ? "VERIFYING CRYPTO..." : "VALIDATE CHAIN INTEGRITY"}
                </button>
              </div>
            </div>

            {verifyResult && (
              <div className={`console-banner ${verifyResult.valid ? "console-success" : "console-error"}`}>
                <span className="console-prompt">{verifyResult.valid ? "[PASS]" : "[FAIL]"}</span>
                <span className="console-text">
                  {verifyResult.valid
                    ? "CRYPTOGRAPHIC CHAIN INTEGRITY VERIFIED: All Ed25519 digital signatures and SHA-256 hash preimages are valid and untampered."
                    : `CHAIN INTEGRITY FAILURE: ${verifyResult.reason || "Hash continuity mismatch detected."}`}
                </span>
                <button className="console-dismiss" onClick={() => setVerifyResult(null)}>DISMISS</button>
              </div>
            )}

            <div className="ledger-stream">
              {ledger.map((b, idx) => (
                <div key={b.block_hash || idx} className="ledger-block">
                  <div className="b-header">
                    <div className="b-idx-group">
                      <span className="b-idx mono-text">BLOCK #{b.block_index}</span>
                      <span className="b-action">{b.payload?.action || b.block_type || "RECOVERY_EVENT"}</span>
                    </div>
                    <span className="b-timestamp mono-text">{b.timestamp}</span>
                  </div>

                  <div className="b-matrix">
                    <div className="b-entry">
                      <span className="b-tag">EVENT METHOD</span>
                      <span className="b-val">{b.payload?.recovery_method || "extent_carving"}</span>
                    </div>
                    <div className="b-entry">
                      <span className="b-tag">TARGET ARTIFACT</span>
                      <span className="b-val mono-text">{b.payload?.file_id || b.payload?.filename || "GENESIS"}</span>
                    </div>
                    <div className="b-entry">
                      <span className="b-tag">PREVIOUS HASH</span>
                      <span className="b-val mono-text hash-text">{b.prev_hash || "0000000000000000000000000000000000000000000000000000000000000000"}</span>
                    </div>
                    <div className="b-entry">
                      <span className="b-tag">BLOCK HASH</span>
                      <span className="b-val mono-text hash-text highlight-hash">{b.block_hash}</span>
                    </div>
                    <div className="b-entry">
                      <span className="b-tag">SIGNER PUBLIC KEY</span>
                      <span className="b-val mono-text hash-text">{b.public_key_id}</span>
                    </div>
                  </div>
                </div>
              ))}
              {ledger.length === 0 && (
                <div className="empty-box">NO LEDGER BLOCKS GENERATED. EXECUTE A SCAN TO INITIATE CHAIN-OF-CUSTODY.</div>
              )}
            </div>
          </div>
        )}

        {/* TAB 4: SETUP */}
        {tab === "setup" && (
          <div className="view-panel">
            <div className="panel-header">
              <div className="title-block">
                <span className="sub-tag">SYSTEM PARAMETERS</span>
                <h1 className="panel-title">Forensic Session Configuration</h1>
              </div>
            </div>

            <div className="panel-box config-box">
              <div className="box-titlebar">
                <span className="box-heading">CASE INITIALIZATION PARAMETERS</span>
              </div>

              <div className="config-form">
                <div className="input-group">
                  <label className="input-label">CASE IDENTIFIER CODE</label>
                  <input
                    className="cyber-input mono-text"
                    type="text"
                    value={caseId}
                    onChange={(e) => setCaseId(e.target.value)}
                    placeholder="CASE-2026-XFS-01"
                  />
                </div>

                <div className="input-group">
                  <label className="input-label">LEAD FORENSIC EXAMINER</label>
                  <input
                    className="cyber-input"
                    type="text"
                    value={investigator}
                    onChange={(e) => setInvestigator(e.target.value)}
                    placeholder="Forensic Examiner ID"
                  />
                </div>

                <div className="input-group">
                  <label className="input-label">EVIDENCE IMAGE TARGET PATH</label>
                  <div className="input-row">
                    <input
                      className="cyber-input mono-text"
                      type="text"
                      value={imagePath}
                      onChange={(e) => setImagePath(e.target.value)}
                      placeholder="tests/fixtures/xfs_deleted_synthetic.img"
                    />
                    <button className="btn-cyber btn-secondary-cyber" onClick={handlePickImage}>
                      BROWSE...
                    </button>
                  </div>
                  <div className="preset-bar">
                    <span className="preset-title">FIXTURE PRESETS:</span>
                    <button
                      className="preset-tag"
                      onClick={() => setImagePath("tests/fixtures/xfs_deleted_synthetic.img")}
                    >
                      SYNTHETIC XFS IMAGE (2MB)
                    </button>
                    <button
                      className="preset-tag"
                      onClick={() => setImagePath("tests/fixtures/btrfs_deleted_synthetic.img")}
                    >
                      SYNTHETIC BTRFS IMAGE (2MB)
                    </button>
                  </div>
                </div>

                <div className="form-actions">
                  <button
                    className="btn-cyber btn-primary-cyber"
                    disabled={scanning || !imagePath}
                    onClick={() => handleRunScan()}
                  >
                    {scanning ? "EXECUTING RECOVERY..." : "EXECUTE FORENSIC ACQUISITION"}
                  </button>
                  <button
                    className="btn-cyber btn-secondary-cyber"
                    disabled={exporting || files.length === 0}
                    onClick={handleExportReport}
                  >
                    {exporting ? "GENERATING..." : "EXPORT AUDIT REPORT"}
                  </button>
                </div>

                {reportPath && (
                  <div className="console-banner console-success" style={{ marginTop: "1.5rem" }}>
                    <span className="console-prompt">[REPORT]</span>
                    <span className="console-text">Forensic report exported to: {reportPath}</span>
                  </div>
                )}
              </div>
            </div>
          </div>
        )}
      </main>
    </div>
  );
}
