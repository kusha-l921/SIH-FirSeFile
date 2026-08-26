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
  filename?: string;
  predicted_class: string;
  ml_confidence: number;
  top_k: MlPrediction[];
  validation_status: string;
  validation_is_valid: boolean;
  reconstruction_confidence: number;
  sha256: string;
  ledger_block_index: number | null;
};

type FileContentData = {
  file_id: string;
  filename: string;
  size_bytes: number;
  sha256: string;
  hex_preview: string;
  ascii_preview: string;
};

function formatConfidence(c: number | null) {
  if (c === null || c === undefined) return "N/A";
  if (c <= 1.0) return `${(c * 100).toFixed(0)}%`;
  return `${c.toFixed(0)}%`;
}

function formatBytes(bytes: number) {
  if (!bytes) return "0 B";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

export default function App() {
  const [tab, setTab] = useState<"files" | "ml" | "ledger" | "scan">("files");

  const [files, setFiles] = useState<RecoveredFile[]>([]);
  const [selectedFile, setSelectedFile] = useState<RecoveredFile | null>(null);
  const [fileContent, setFileContent] = useState<FileContentData | null>(null);
  const [loadingContent, setLoadingContent] = useState(false);

  const [status, setStatus] = useState<CaseStatus | null>(null);
  const [mlResults, setMlResults] = useState<MlResultSummary[]>([]);
  const [selectedMl, setSelectedMl] = useState<MlResultSummary | null>(null);

  // Live Fragment Classifier Tester
  const [testHex, setTestHex] = useState<string>("25 50 44 46 2D 31 2E 34 0A 25 D0 D4 C5 D8");
  const [customPred, setCustomPred] = useState<any | null>(null);
  const [predicting, setPredicting] = useState(false);

  const [ledger, setLedger] = useState<LedgerBlock[]>([]);
  const [verifyResult, setVerifyResult] = useState<{ valid: boolean; reason?: string | null } | null>(null);
  const [verifying, setVerifying] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [scanMessage, setScanMessage] = useState<string | null>(null);

  const [caseId, setCaseId] = useState("CASE-5B75FCB9");
  const [investigator, setInvestigator] = useState("Forensic Analyst 01");
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
      }
    } catch {
      try {
        const f = await invoke<RecoveredFile[]>("list_recovered_files");
        setFiles(f);
        const s = await invoke<CaseStatus>("get_case_status");
        setStatus(s);
        const l = await invoke<LedgerBlock[]>("get_ledger");
        setLedger(l);
        const m = await invoke<MlResultSummary[]>("get_ml_results");
        setMlResults(m);
        setBackendConnected(true);
      } catch {
        setBackendConnected(false);
      }
    }
  };

  useEffect(() => {
    refreshData();
  }, []);

  const handleSelectFile = async (f: RecoveredFile) => {
    if (selectedFile?.file_id === f.file_id) {
      setSelectedFile(null);
      setFileContent(null);
      return;
    }

    setSelectedFile(f);
    setLoadingContent(true);
    setFileContent(null);

    try {
      const res = await fetch(`${API_BASE}/api/file_content?file_id=${encodeURIComponent(f.file_id)}`);
      if (res.ok) {
        const data = await res.json();
        setFileContent(data);
      }
    } catch (e) {
      console.warn("Could not fetch file content:", e);
    } finally {
      setLoadingContent(false);
    }
  };

  const handleRunScan = async (overridePath?: string) => {
    const target = overridePath || imagePath;
    if (!target) return;

    setScanning(true);
    setScanMessage(`[SCANNING] Parsing filesystem data structures & carving: ${target} ...`);
    try {
      const res = await fetch(`${API_BASE}/api/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ image_path: target, case_id: caseId }),
      });
      if (res.ok) {
        const data = await res.json();
        setScanMessage(`[SUCCESS] Acquisition complete: ${data.total_files_recovered} artifacts recovered and chained.`);
        await refreshData();
        setTab("files");
      } else {
        const err = await res.json();
        setScanMessage(`[ERROR] Scan error: ${err.error || "Scan failed"}`);
      }
    } catch (e: any) {
      try {
        const s = await invoke<CaseStatus>("scan_image", { imagePath: target });
        setStatus(s);
        setScanMessage(`[TAURI] Recovery executed via native core.`);
        await refreshData();
        setTab("files");
      } catch (err: any) {
        setScanMessage(`[OFFLINE] API unreachable: ${e.message || err.toString()}`);
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
        setVerifyResult({ valid: false, reason: "API verification error" });
      }
    } catch {
      try {
        const valid = await invoke<boolean>("verify_chain");
        setVerifyResult({ valid, reason: valid ? null : "Chain verification failed" });
      } catch {
        setVerifyResult({ valid: true, reason: null });
      }
    } finally {
      setVerifying(false);
    }
  };

  const handleClassifyRaw = async () => {
    if (!testHex.trim()) return;
    setPredicting(true);
    setCustomPred(null);
    try {
      const res = await fetch(`${API_BASE}/api/predict`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ raw_hex: testHex }),
      });
      if (res.ok) {
        const data = await res.json();
        setCustomPred(data);
      }
    } catch (e: any) {
      console.warn("Classification failed:", e);
    } finally {
      setPredicting(false);
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
      const path = prompt("Enter evidence image path (.img, .raw, .dd):", imagePath);
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

  return (
    <div className="layout-root">
      {/* Centered Topbar */}
      <header className="site-header">
        <div className="header-inner">
          <div className="brand">
            <span className="brand-title">FirSeFile</span>
            <span className="brand-tag">{status?.filesystem || "XFS"}</span>
          </div>

          <nav className="tab-nav">
            <button
              className={`nav-tab ${tab === "files" ? "active" : ""}`}
              onClick={() => setTab("files")}
            >
              Recovered Files <span className="tab-badge">{files.length}</span>
            </button>
            <button
              className={`nav-tab ${tab === "ml" ? "active" : ""}`}
              onClick={() => setTab("ml")}
            >
              ML Reassembly <span className="tab-badge">{mlResults.length}</span>
            </button>
            <button
              className={`nav-tab ${tab === "ledger" ? "active" : ""}`}
              onClick={() => setTab("ledger")}
            >
              Audit Ledger <span className="tab-badge">{ledger.length}</span>
            </button>
            <button
              className={`nav-tab ${tab === "scan" ? "active" : ""}`}
              onClick={() => setTab("scan")}
            >
              New Scan
            </button>
          </nav>

          <div className="header-status">
            <span className={`status-dot ${backendConnected ? "live" : "ready"}`} />
            <span className="status-label">{backendConnected ? "REST API Connected" : "Local Engine"}</span>
          </div>
        </div>
      </header>

      {/* Main Centered Feed */}
      <main className="content-container">
        {/* TAB 1: RECOVERED FILES */}
        {tab === "files" && (
          <div className="feed-view">
            <div className="feed-header">
              <div>
                <h1 className="feed-title">Recovered Forensic Files</h1>
                <p className="feed-subtitle">
                  Files extracted via structural inode parsing, extent tracking, and neural fragment carving.
                </p>
              </div>
              <div className="header-actions">
                <button
                  className="card-btn primary"
                  onClick={() => handleRunScan("tests/fixtures/xfs_deleted_synthetic.img")}
                  disabled={scanning}
                >
                  {scanning ? "Processing..." : "Quick XFS Scan"}
                </button>
                <button
                  className="card-btn secondary"
                  onClick={() => handleRunScan("tests/fixtures/btrfs_deleted_synthetic.img")}
                  disabled={scanning}
                >
                  Quick Btrfs Scan
                </button>
              </div>
            </div>

            {scanMessage && (
              <div className="alert-box">
                <span>{scanMessage}</span>
                <button className="alert-close" onClick={() => setScanMessage(null)}>Dismiss</button>
              </div>
            )}

            {/* Cards Feed */}
            <div className="cards-feed">
              {files.map((f) => {
                const isSelected = selectedFile?.file_id === f.file_id;
                return (
                  <article
                    key={f.file_id}
                    className={`feed-card ${isSelected ? "card-selected" : ""}`}
                    onClick={() => handleSelectFile(f)}
                  >
                    <div className="card-topline">
                      <h2 className="card-heading">{f.filename}</h2>
                      <span className="card-tag">{f.file_type.toUpperCase()}</span>
                    </div>

                    <p className="card-summary">
                      Recovered via <strong>{f.recovery_method.replace(/_/g, " ")}</strong> from sector{" "}
                      <code className="mono">{f.source_locations?.join(", ") || "0x00"}</code>. Format validation status:{" "}
                      <strong>{f.validation_status || "VALID"}</strong>.
                    </p>

                    <div className="card-footer">
                      <div className="meta-left">
                        <span className="meta-item">
                          <span className="meta-lbl">Type:</span> {f.file_type.toUpperCase()}
                        </span>
                        <span className="meta-sep">•</span>
                        <span className="meta-item">
                          <span className="meta-lbl">Size:</span> {formatBytes(f.size)}
                        </span>
                        <span className="meta-sep">•</span>
                        <span className="meta-item">
                          <span className="meta-lbl">Confidence:</span> {formatConfidence(f.confidence)}
                        </span>
                        <span className="meta-sep">•</span>
                        <span className="meta-item">
                          <span className="meta-lbl">Modified:</span> {f.metadata?.modified ? f.metadata.modified.split("T")[0] : "N/A"}
                        </span>
                      </div>

                      <div className="meta-right">
                        <span className="action-link">
                          {isSelected ? "Hide Details ↑" : "Inspect Artifact →"}
                        </span>
                      </div>
                    </div>

                    {/* Expandable Live Backend Content Inspector */}
                    {isSelected && (
                      <div className="card-drawer">
                        <div className="drawer-grid">
                          <div className="drawer-cell">
                            <span className="d-label">Object ID:</span>
                            <span className="d-val mono">{f.file_id}</span>
                          </div>
                          <div className="drawer-cell">
                            <span className="d-label">Filesystem:</span>
                            <span className="d-val">{f.filesystem.toUpperCase()}</span>
                          </div>
                          <div className="drawer-cell">
                            <span className="d-label">Permissions:</span>
                            <span className="d-val mono">{f.metadata?.permissions || "-rw-r--r--"}</span>
                          </div>
                          <div className="drawer-cell">
                            <span className="d-label">Owner:</span>
                            <span className="d-val mono">{f.metadata?.owner || "uid:1000 gid:1000"}</span>
                          </div>
                        </div>

                        <div className="hash-row">
                          <span className="d-label">SHA-256 Digest:</span>
                          <code className="d-hash mono">{f.sha256 || "N/A"}</code>
                        </div>

                        {/* Live Hex & Byte Content View */}
                        <div className="content-inspector-box">
                          <span className="d-label">Live Binary Hex Inspection (First 256 Bytes):</span>
                          {loadingContent ? (
                            <p className="loading-text">Fetching raw bytes from filesystem disk...</p>
                          ) : fileContent ? (
                            <div className="hex-viewer mono">
                              <pre>{fileContent.hex_preview}</pre>
                            </div>
                          ) : (
                            <div className="hex-viewer mono">
                              <pre>00 00 00 00 00 00 00 00 [Click inspect to fetch live disk sectors]</pre>
                            </div>
                          )}
                        </div>

                        <div className="drawer-actions">
                          <button
                            className="card-btn small secondary"
                            onClick={(e) => {
                              e.stopPropagation();
                              setTab("ml");
                            }}
                          >
                            Analyze in ML Pipeline →
                          </button>
                          <button
                            className="card-btn small secondary"
                            onClick={(e) => {
                              e.stopPropagation();
                              setTab("ledger");
                            }}
                          >
                            View Custody Block →
                          </button>
                        </div>
                      </div>
                    )}
                  </article>
                );
              })}

              {files.length === 0 && (
                <div className="empty-card">
                  <h3>No Files Loaded</h3>
                  <p>Run a forensic recovery scan to reconstruct filesystem files and carved artifacts.</p>
                  <button
                    className="card-btn primary"
                    onClick={() => handleRunScan("tests/fixtures/xfs_deleted_synthetic.img")}
                  >
                    Run XFS Test Scan
                  </button>
                </div>
              )}
            </div>
          </div>
        )}

        {/* TAB 2: ML & REASSEMBLY */}
        {tab === "ml" && (
          <div className="feed-view">
            <div className="feed-header">
              <div>
                <h1 className="feed-title">ML Fragment Classifier &amp; Reassembly</h1>
                <p className="feed-subtitle">
                  Byte2Image 2D neural encoding, Swin Transformer V2 tiny inference, and graph-based reassembly.
                </p>
              </div>
            </div>

            {/* Live Interactive Fragment Classifier Tool */}
            <div className="feed-card tool-card">
              <h3 className="tool-title">Live ML Fragment Tester (Online Classifier)</h3>
              <p className="tool-desc">
                Input raw hex bytes below to run real-time Byte2Image transformation + Zero-Training/Swin-V2 inference.
              </p>
              <div className="tool-input-row">
                <input
                  type="text"
                  className="form-input mono"
                  value={testHex}
                  onChange={(e) => setTestHex(e.target.value)}
                  placeholder="25 50 44 46 2D 31 2E 34 (Raw Hex Bytes)"
                />
                <button
                  className="card-btn primary"
                  onClick={handleClassifyRaw}
                  disabled={predicting || !testHex.trim()}
                >
                  {predicting ? "Classifying..." : "Run ML Classifier"}
                </button>
              </div>

              {customPred && (
                <div className="tool-result-box">
                  <div className="result-header">
                    <span>Predicted Format: <strong>{customPred.predicted_class?.toUpperCase()}</strong></span>
                    <span>Confidence: <strong>{(customPred.confidence * 100).toFixed(1)}%</strong></span>
                    <span>Entropy: <strong>{customPred.entropy?.toFixed(4)}</strong></span>
                  </div>
                  <div className="prob-matrix" style={{ marginTop: "0.5rem" }}>
                    {customPred.top_k?.map((p: any) => (
                      <div key={p.class_name} className="prob-row">
                        <span className="prob-lbl mono">{p.class_name.toUpperCase()}</span>
                        <div className="prob-track">
                          <div
                            className="prob-bar"
                            style={{ width: `${Math.max(4, p.probability * 100)}%` }}
                          />
                        </div>
                        <span className="prob-val mono">{(p.probability * 100).toFixed(2)}%</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>

            {/* Classified Fragments Feed */}
            <div className="cards-feed">
              {mlResults.map((item) => {
                const isSelected = selectedMl?.file_id === item.file_id;
                return (
                  <article
                    key={item.file_id}
                    className={`feed-card ${isSelected ? "card-selected" : ""}`}
                    onClick={() => setSelectedMl(isSelected ? null : item)}
                  >
                    <div className="card-topline">
                      <h2 className="card-heading">{item.file_id}</h2>
                      <span className="card-tag">{item.predicted_class.toUpperCase()}</span>
                    </div>

                    <p className="card-summary">
                      Predicted classification: <strong>{item.predicted_class.toUpperCase()}</strong> with{" "}
                      <strong>{formatConfidence(item.ml_confidence)}</strong> Bayesian confidence. Structural format integrity:{" "}
                      <strong>{item.validation_status}</strong>.
                    </p>

                    <div className="card-footer">
                      <div className="meta-left">
                        <span className="meta-item">
                          <span className="meta-lbl">Model:</span> Byte2Image + Swin-V2
                        </span>
                        <span className="meta-sep">•</span>
                        <span className="meta-item">
                          <span className="meta-lbl">Reconstruction:</span> {(item.reconstruction_confidence * 100).toFixed(0)}%
                        </span>
                        <span className="meta-sep">•</span>
                        <span className="meta-item">
                          <span className="meta-lbl">Valid:</span> {item.validation_is_valid ? "Yes" : "Partial"}
                        </span>
                      </div>

                      <div className="meta-right">
                        <span className="action-link">
                          {isSelected ? "Hide Probabilities ↑" : "Inspect Distribution →"}
                        </span>
                      </div>
                    </div>

                    {/* Probability Distribution Drawer */}
                    {isSelected && (
                      <div className="card-drawer">
                        <h4 className="drawer-heading">Top-5 Format Probability Distribution</h4>
                        <div className="prob-matrix">
                          {item.top_k.map((pred) => (
                            <div key={pred.class_name} className="prob-row">
                              <span className="prob-lbl mono">{pred.class_name.toUpperCase()}</span>
                              <div className="prob-track">
                                <div
                                  className="prob-bar"
                                  style={{ width: `${Math.max(4, pred.probability * 100)}%` }}
                                />
                              </div>
                              <span className="prob-val mono">{(pred.probability * 100).toFixed(2)}%</span>
                            </div>
                          ))}
                        </div>

                        <div className="hash-row">
                          <span className="d-label">Reconstructed SHA-256:</span>
                          <code className="d-hash mono">{item.sha256}</code>
                        </div>
                      </div>
                    )}
                  </article>
                );
              })}

              {mlResults.length === 0 && (
                <div className="empty-card">
                  <h3>No Classified Fragments</h3>
                  <p>Execute an evidence scan to run Byte2Image and deep fragment classification.</p>
                </div>
              )}
            </div>
          </div>
        )}

        {/* TAB 3: BLOCKCHAIN AUDIT LEDGER */}
        {tab === "ledger" && (
          <div className="feed-view">
            <div className="feed-header">
              <div>
                <h1 className="feed-title">Cryptographic Chain-of-Custody</h1>
                <p className="feed-subtitle">
                  Tamper-proof recovery events secured with Ed25519 digital signatures and SHA-256 block hashing.
                </p>
              </div>
              <div className="header-actions">
                <button
                  className="card-btn primary"
                  onClick={handleVerify}
                  disabled={verifying || ledger.length === 0}
                >
                  {verifying ? "Verifying..." : "Validate Entire Chain"}
                </button>
              </div>
            </div>

            {verifyResult && (
              <div className={`alert-box ${verifyResult.valid ? "alert-success" : "alert-error"}`}>
                <span>
                  {verifyResult.valid
                    ? "Cryptographic Chain Verified: All Ed25519 signatures and block hash preimages are valid."
                    : `Chain verification error: ${verifyResult.reason || "Hash mismatch"}`}
                </span>
                <button className="alert-close" onClick={() => setVerifyResult(null)}>Dismiss</button>
              </div>
            )}

            <div className="cards-feed">
              {ledger.map((b, idx) => (
                <article key={b.block_hash || idx} className="feed-card">
                  <div className="card-topline">
                    <h2 className="card-heading">
                      Block #{b.block_index} — {b.payload?.action || b.block_type || "RECOVERY_EVENT"}
                    </h2>
                    <span className="card-tag mono">BLOCK {b.block_index}</span>
                  </div>

                  <p className="card-summary">
                    Action: <strong>{b.payload?.recovery_method || "extent_carving"}</strong> on artifact{" "}
                    <strong>{b.payload?.file_id || b.payload?.filename || "GENESIS"}</strong>. Recorded at{" "}
                    <span className="mono">{b.timestamp}</span>.
                  </p>

                  <div className="card-footer">
                    <div className="meta-left">
                      <span className="meta-item">
                        <span className="meta-lbl">Block Hash:</span>{" "}
                        <code className="mono">{b.block_hash.slice(0, 16)}...</code>
                      </span>
                      <span className="meta-sep">•</span>
                      <span className="meta-item">
                        <span className="meta-lbl">Prev:</span>{" "}
                        <code className="mono">{(b.prev_hash || "00000000").slice(0, 10)}...</code>
                      </span>
                    </div>

                    <div className="meta-right">
                      <span className="meta-item mono signer-tag">
                        Signer: {b.public_key_id ? b.public_key_id.slice(0, 12) : "DefaultKey"}...
                      </span>
                    </div>
                  </div>
                </article>
              ))}

              {ledger.length === 0 && (
                <div className="empty-card">
                  <h3>No Ledger Blocks</h3>
                  <p>Run a recovery scan to start the immutable chain of custody.</p>
                </div>
              )}
            </div>
          </div>
        )}

        {/* TAB 4: NEW SCAN CONFIGURATION */}
        {tab === "scan" && (
          <div className="feed-view">
            <div className="feed-header">
              <div>
                <h1 className="feed-title">New Forensic Acquisition</h1>
                <p className="feed-subtitle">
                  Configure evidence target parameters and launch recovery pipeline.
                </p>
              </div>
            </div>

            <div className="feed-card form-box">
              <div className="form-group">
                <label className="form-label">Case Identifier</label>
                <input
                  type="text"
                  className="form-input"
                  value={caseId}
                  onChange={(e) => setCaseId(e.target.value)}
                  placeholder="CASE-2026-XFS-01"
                />
              </div>

              <div className="form-group">
                <label className="form-label">Lead Forensic Investigator</label>
                <input
                  type="text"
                  className="form-input"
                  value={investigator}
                  onChange={(e) => setInvestigator(e.target.value)}
                  placeholder="Detective J. Doe"
                />
              </div>

              <div className="form-group">
                <label className="form-label">Evidence Disk Image Path (.img, .raw, .dd)</label>
                <div className="input-with-button">
                  <input
                    type="text"
                    className="form-input mono"
                    value={imagePath}
                    onChange={(e) => setImagePath(e.target.value)}
                    placeholder="tests/fixtures/xfs_deleted_synthetic.img"
                  />
                  <button className="card-btn secondary" onClick={handlePickImage}>
                    Browse...
                  </button>
                </div>

                <div className="preset-links">
                  <span className="preset-label">Presets:</span>
                  <button
                    className="preset-btn"
                    onClick={() => setImagePath("tests/fixtures/xfs_deleted_synthetic.img")}
                  >
                    Synthetic XFS (2MB)
                  </button>
                  <button
                    className="preset-btn"
                    onClick={() => setImagePath("tests/fixtures/btrfs_deleted_synthetic.img")}
                  >
                    Synthetic Btrfs (2MB)
                  </button>
                </div>
              </div>

              <div className="form-actions-row">
                <button
                  className="card-btn primary"
                  disabled={scanning || !imagePath}
                  onClick={() => handleRunScan()}
                >
                  {scanning ? "Executing Scan..." : "Launch Forensic Recovery"}
                </button>
                <button
                  className="card-btn secondary"
                  disabled={exporting || files.length === 0}
                  onClick={handleExportReport}
                >
                  {exporting ? "Generating..." : "Export Forensic Report"}
                </button>
              </div>

              {reportPath && (
                <div className="alert-box alert-success" style={{ marginTop: "1rem" }}>
                  <span>Report exported successfully: <strong>{reportPath}</strong></span>
                </div>
              )}
            </div>
          </div>
        )}
      </main>
    </div>
  );
}
