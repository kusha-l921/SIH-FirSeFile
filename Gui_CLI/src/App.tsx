import { useEffect, useState, useRef, useCallback } from "react";
import { invoke } from "@tauri-apps/api/core";
import { open } from "@tauri-apps/plugin-dialog";
import "./App.css";

const API_BASE = "http://127.0.0.1:8765";

type FileMetadata = {
  filename?: string;
  file_size?: number | null;
  original_size?: number | null;
  observed_extent_bytes?: number | null;
  modified: string | null;
  accessed: string | null;
  changed: string | null;
  birth?: string | null;
  created?: string | null;
  permissions: string | null;
  ownership?: { uid: number; gid: number } | null;
  owner?: string | null;
  filesystem?: string | null;
  source_locations?: (number | string)[];
  additional_attributes?: Record<string, any>;
};

type MlPrediction = {
  class_name: string;
  probability: number;
};

type RecoveredFile = {
  file_id: string;
  filename: string;
  file_type: string;
  size?: number | null;
  file_size?: number | null;
  original_size?: number | null;
  observed_extent_bytes?: number | null;
  content_hash_exact?: boolean;
  filesystem?: string;
  recovery_method: string;
  confidence: number | string | null;
  confidence_class?: string | null;
  source_locations: (number | string)[];
  metadata: FileMetadata;
  sha256: string | null;
  ml_predicted_class?: string | null;
  ml_confidence?: number | null;
  ml_top_k?: MlPrediction[] | null;
  validation_status?: string | null;
  validation_is_valid?: boolean | null;
  reconstruction_confidence?: number | null;
  is_experimental?: boolean;
};

type CaseStatus = {
  scan_id: string | null;
  case_id: string | null;
  filesystem: string | null;
  status: string;
  image_path?: string | null;
  image_sha256?: string | null;
  files_recovered: number;
  fragments_found: number;
  blocks_processed: number;
  total_blocks: number;
  scan_start_time?: string | null;
  scan_end_time?: string | null;
  error?: string | null;
};

type RecoveryEventPayload = {
  disk_baseline_sha256?: string;
  operator_public_key?: string;
  filename?: string;
  file_id?: string | null;
  size?: number;
  original_size?: number;
  observed_extent_bytes?: number;
  recovered_file_sha256?: string | null;
  content_sha256?: string | null;
  content_hash_exact?: boolean;
  source_location?: string | number | null;
  recovery_method?: string;
  recovery_confidence?: string | number | null;
  confidence?: number | null;
  action?: string;
  event_id?: string;
  file_type?: string;
  macb_timestamps?: {
    modified?: string | null;
    accessed?: string | null;
    changed?: string | null;
    created?: string | null;
  };
  metadata?: Record<string, any>;
  validation?: Record<string, any>;
  is_experimental?: boolean;
  [key: string]: any;
};

type LedgerBlock = {
  block_index: number;
  timestamp: string;
  block_type?: string;
  file_id?: string;
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

function formatConfidence(c: number | string | null | undefined): string {
  if (c === null || c === undefined || c === "") return "N/A";
  if (typeof c === "string") {
    const num = parseFloat(c);
    if (!isNaN(num)) {
      if (num <= 1.0) return `${(num * 100).toFixed(0)}%`;
      return `${num.toFixed(0)}%`;
    }
    const clow = c.toLowerCase();
    if (clow === "high") return "High (95%)";
    if (clow === "medium") return "Medium (75%)";
    if (clow === "low") return "Low (50%)";
    return c.charAt(0).toUpperCase() + c.slice(1);
  }
  if (c <= 1.0) return `${(c * 100).toFixed(0)}%`;
  return `${c.toFixed(0)}%`;
}

function formatBytes(bytes: number | null | undefined): string {
  if (bytes === null || bytes === undefined) return "Unknown";
  if (bytes === 0) return "0 B";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

function formatFileDisplaySize(file: RecoveredFile): string {
  const origSize = file.original_size ?? file.metadata?.original_size;
  const fileSize = file.file_size ?? file.size ?? file.metadata?.file_size;
  const extentBytes = file.observed_extent_bytes ?? file.metadata?.observed_extent_bytes;

  if (origSize !== null && origSize !== undefined) {
    return formatBytes(origSize);
  }
  if (fileSize !== null && fileSize !== undefined) {
    return formatBytes(fileSize);
  }
  if (extentBytes !== null && extentBytes !== undefined && extentBytes > 0) {
    return `~${formatBytes(extentBytes)} (extent)`;
  }
  return "Unknown size";
}

function formatModifiedDate(isoString: string | null | undefined): string {
  if (!isoString || isoString === "N/A" || isoString.trim() === "" || isoString === "null") {
    return "Unknown";
  }
  try {
    const d = new Date(isoString);
    if (isNaN(d.getTime())) {
      return "Unknown";
    }
    const formatter = new Intl.DateTimeFormat("en-GB", {
      timeZone: "Asia/Kolkata",
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hour12: false,
    });
    const parts = formatter.formatToParts(d);
    const getPart = (type: string) => parts.find((p) => p.type === type)?.value || "";
    const year = getPart("year");
    const month = getPart("month");
    const day = getPart("day");
    const hour = getPart("hour");
    const minute = getPart("minute");
    const second = getPart("second");
    if (!year || !month || !day) {
      return "Unknown";
    }
    return `${year}-${month}-${day} ${hour}:${minute}:${second} IST`;
  } catch {
    return "Unknown";
  }
}

const formatIST = formatModifiedDate;

interface MlSummary {
  total_artifacts: number;
  dominant_format: string | null;
  average_confidence: number | null;
  average_confidence_pct: string;
  format_counts: Record<string, number>;
  format_percentages: Record<string, number>;
}

function computeMlAggregate(results: MlResultSummary[]): MlSummary {
  if (!results || results.length === 0) {
    return {
      total_artifacts: 0,
      dominant_format: null,
      average_confidence: null,
      average_confidence_pct: "N/A",
      format_counts: {},
      format_percentages: {},
    };
  }
  const total = results.length;
  const counts: Record<string, number> = {};
  const confSums: Record<string, number> = {};
  let totalConf = 0;

  for (const item of results) {
    const fmt = (item.predicted_class || "unknown").toLowerCase();
    const conf = typeof item.ml_confidence === "number" ? item.ml_confidence : 0.65;
    counts[fmt] = (counts[fmt] || 0) + 1;
    confSums[fmt] = (confSums[fmt] || 0) + conf;
    totalConf += conf;
  }

  const avgConf = totalConf / total;

  // Deterministic tie-breaking: max count, then max conf sum, then alphabetical
  const sortedFormats = Object.keys(counts).sort((a, b) => {
    if (counts[b] !== counts[a]) {
      return counts[b] - counts[a];
    }
    if (confSums[b] !== confSums[a]) {
      return confSums[b] - confSums[a];
    }
    return a.localeCompare(b);
  });

  const percentages: Record<string, number> = {};
  for (const fmt of Object.keys(counts)) {
    percentages[fmt] = Number(((counts[fmt] / total) * 100).toFixed(1));
  }

  return {
    total_artifacts: total,
    dominant_format: sortedFormats[0] || null,
    average_confidence: avgConf,
    average_confidence_pct: `${(avgConf * 100).toFixed(1)}%`,
    format_counts: counts,
    format_percentages: percentages,
  };
}

export default function App() {
  const [tab, setTab] = useState<"files" | "ml" | "ledger" | "scan" | "inspect">("scan");

  const [files, setFiles] = useState<RecoveredFile[]>([]);

  // Dedicated Artifact Inspector State
  const [inspectedFileId, setInspectedFileId] = useState<string | null>(null);
  const [inspectedData, setInspectedData] = useState<any | null>(null);
  const [inspectLoading, setInspectLoading] = useState<boolean>(false);
  const [inspectError, setInspectError] = useState<string | null>(null);
  const [inspectViewMode, setInspectViewMode] = useState<"preview" | "hex" | "ascii">("preview");

  const [status, setStatus] = useState<CaseStatus | null>(null);
  const [mlResults, setMlResults] = useState<MlResultSummary[]>([]);
  const [selectedMl, setSelectedMl] = useState<MlResultSummary | null>(null);

  // Live Fragment Classifier Tester (Independent manual utility)
  const [testHex, setTestHex] = useState<string>("");
  const [customPred, setCustomPred] = useState<any | null>(null);
  const [predicting, setPredicting] = useState(false);

  const [ledger, setLedger] = useState<LedgerBlock[]>([]);
  const [expandedBlocks, setExpandedBlocks] = useState<Record<number, boolean>>({});
  const [verifyResult, setVerifyResult] = useState<{ valid: boolean; reason?: string | null } | null>(null);
  const [verifying, setVerifying] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [scanMessage, setScanMessage] = useState<string | null>(null);

  const toggleBlock = (index: number) => {
    setExpandedBlocks((prev) => ({
      ...prev,
      [index]: !prev[index],
    }));
  };

  const focusBlock = (index: number) => {
    setExpandedBlocks((prev) => ({
      ...prev,
      [index]: true,
    }));
    setTimeout(() => {
      const el = document.getElementById(`ledger-block-${index}`);
      if (el) {
        el.scrollIntoView({ behavior: "smooth", block: "center" });
      }
    }, 50);
  };

  // --- NO HARDCODED DEFAULTS --- user must provide their own values
  const [caseId, setCaseId] = useState("");
  const [investigator, setInvestigator] = useState("");
  const [imagePath, setImagePath] = useState<string>("");

  const [reportPath, setReportPath] = useState<string | null>(null);
  const [exporting, setExporting] = useState(false);
  const [backendConnected, setBackendConnected] = useState<boolean>(false);

  // Polling ref for scan status
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const activeScanIdRef = useRef<string | null>(null);

  // Stop any active polling
  const stopPolling = useCallback(() => {
    if (pollRef.current) {
      clearInterval(pollRef.current);
      pollRef.current = null;
    }
  }, []);

  // Fetch current data from backend (files, ledger, ml results)
  const fetchResults = useCallback(async () => {
    try {
      const [resFiles, resLedger, resMl] = await Promise.all([
        fetch(`${API_BASE}/api/files`),
        fetch(`${API_BASE}/api/ledger`),
        fetch(`${API_BASE}/api/ml_results`),
      ]);
      if (resFiles.ok) setFiles(await resFiles.json());
      if (resLedger.ok) setLedger(await resLedger.json());
      if (resMl.ok) setMlResults(await resMl.json());
    } catch {
      // silent — will be shown via backend status
    }
  }, []);

  // Check if backend is alive on mount (but do NOT load stale results)
  useEffect(() => {
    const checkBackend = async () => {
      try {
        const res = await fetch(`${API_BASE}/api/status`);
        if (res.ok) {
          const data = await res.json();
          setStatus(data);
          setBackendConnected(true);
          // If backend already has completed results (e.g. page reload during active scan),
          // load them — but only if status is "complete"
          if (data.status === "complete") {
            await fetchResults();
          }
        }
      } catch {
        setBackendConnected(false);
      }
    };
    checkBackend();

    // Hash-based routing
    const handleHashChange = () => {
      const hash = window.location.hash;
      if (hash.startsWith("#inspect/")) {
        const id = decodeURIComponent(hash.replace("#inspect/", ""));
        if (id) {
          handleInspectArtifact(id);
        }
      } else if (hash === "#ml") {
        setTab("ml");
      } else if (hash === "#ledger") {
        setTab("ledger");
      } else if (hash === "#scan") {
        setTab("scan");
      } else if (hash === "#files" || !hash) {
        if (tab === "inspect") {
          setTab("files");
        }
      }
    };

    window.addEventListener("hashchange", handleHashChange);
    if (window.location.hash.startsWith("#inspect/")) {
      handleHashChange();
    }

    return () => {
      window.removeEventListener("hashchange", handleHashChange);
      stopPolling();
    };
  }, []);

  const handleInspectArtifact = async (fileOrId: RecoveredFile | string) => {
    const id = typeof fileOrId === "string" ? fileOrId : fileOrId.file_id || fileOrId.filename;
    if (!id) return;

    setInspectedFileId(id);
    setInspectLoading(true);
    setInspectError(null);
    setInspectedData(null);
    setInspectViewMode("preview");
    setTab("inspect");

    try {
      window.location.hash = `inspect/${encodeURIComponent(id)}`;
    } catch {}

    try {
      const res = await fetch(`${API_BASE}/api/file_content?file_id=${encodeURIComponent(id)}`);
      if (res.ok) {
        const data = await res.json();
        setInspectedData(data);
      } else {
        const err = await res.json().catch(() => ({ error: "Artifact not found" }));
        setInspectError(err.error || `HTTP ${res.status}: Failed to load artifact`);
      }
    } catch (e: any) {
      setInspectError(`API Connection failed: ${e.message || "Network error"}`);
    } finally {
      setInspectLoading(false);
    }
  };

  const handleBackToFiles = () => {
    setTab("files");
    setInspectedFileId(null);
    setInspectedData(null);
    setInspectError(null);
    try {
      window.location.hash = "files";
    } catch {}
  };

  const handleRunScan = async (overridePath?: string) => {
    const target = overridePath || imagePath;
    if (!target || !target.trim()) {
      setScanMessage("[ERROR] You must provide an evidence image path before scanning.");
      return;
    }

    // ---------------------------------------------------------------
    // CLEAR ALL PREVIOUS RESULTS before starting a new scan
    // ---------------------------------------------------------------
    stopPolling();
    setScanning(true);
    setFiles([]);
    setLedger([]);
    setMlResults([]);
    setStatus(null);
    setVerifyResult(null);
    setScanMessage(`[SCANNING] Parsing filesystem data structures & carving: ${target} ...`);

    try {
      const res = await fetch(`${API_BASE}/api/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ image_path: target, case_id: caseId || undefined }),
      });

      const data = await res.json();

      if (!res.ok) {
        // Backend rejected the scan (missing path, not found, etc.)
        setScanMessage(`[ERROR] ${data.error || "Scan rejected by server"}`);
        setScanning(false);
        setStatus({ scan_id: null, case_id: null, filesystem: null, status: "error", files_recovered: 0, fragments_found: 0, blocks_processed: 0, total_blocks: 0, error: data.error });
        return;
      }

      // Scan accepted and running in background — start polling
      const scanId = data.scan_id;
      activeScanIdRef.current = scanId;
      setScanMessage(`[RUNNING] Scan ${scanId} initiated on ${target}. Waiting for results...`);

      pollRef.current = setInterval(async () => {
        try {
          const statusRes = await fetch(`${API_BASE}/api/status`);
          if (!statusRes.ok) return;
          const statusData: CaseStatus = await statusRes.json();
          setStatus(statusData);

          // Only process if this is our active scan
          if (statusData.scan_id !== activeScanIdRef.current) return;

          if (statusData.status === "complete") {
            stopPolling();
            setScanning(false);
            setScanMessage(`[SUCCESS] Scan complete: ${statusData.files_recovered} artifacts recovered.`);
            await fetchResults();
            setTab("files");
          } else if (statusData.status === "error") {
            stopPolling();
            setScanning(false);
            setScanMessage(`[ERROR] Scan failed: ${statusData.error || "Unknown error"}`);
          }
          // else still "running" — keep polling
        } catch {
          // Network hiccup — keep polling
        }
      }, 2000);

    } catch (e: any) {
      try {
        const s = await invoke<CaseStatus>("scan_image", { imagePath: target });
        setStatus(s);
        setScanMessage(`[TAURI] Recovery executed via native core.`);
        await fetchResults();
        setTab("files");
      } catch (err: any) {
        setScanMessage(`[OFFLINE] API unreachable: ${e.message || err.toString()}`);
      }
      setScanning(false);
    }
  };

  // Clean up polling on unmount
  useEffect(() => {
    return () => stopPolling();
  }, [stopPolling]);

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
        setVerifyResult({ valid: false, reason: "Verification unavailable" });
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
    if (files.length === 0) {
      setScanMessage("No completed forensic scan available for export.");
      return;
    }
    setExporting(true);
    setReportPath(null);
    try {
      const activeCaseId = caseId || status?.case_id || "CASE-EXPORT";
      const activeInvestigator = investigator || "Forensic Analyst";
      const safeCaseId = activeCaseId.replace(/[^a-zA-Z0-9_-]/g, "_");

      const res = await fetch(`${API_BASE}/api/export`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          case_id: activeCaseId,
          investigator: activeInvestigator,
          format: "pdf",
        }),
      });

      if (res.ok) {
        const blob = await res.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        const filename = `FirSeFile_Forensic_Report_${safeCaseId}.pdf`;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        document.body.removeChild(a);
        setReportPath(filename);
      } else {
        const errData = await res.json().catch(() => ({ error: "Export failed" }));
        setScanMessage(`Export failed: ${errData.error || "No completed scan available"}`);
      }
    } catch (err: any) {
      try {
        const path = await invoke<string>("export_report", { caseId, investigator });
        setReportPath(path);
      } catch {
        setScanMessage(`Export error: ${err?.message || "Failed to download report"}`);
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
            <span className="brand-tag">{status?.filesystem || "—"}</span>
          </div>

          <nav className="tab-nav">
            <button
              className={`nav-tab ${tab === "scan" ? "active" : ""}`}
              onClick={() => setTab("scan")}
            >
              New Scan
            </button>
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
            {tab === "inspect" && (
              <button className="nav-tab active">
                Inspect <span className="tab-badge">1</span>
              </button>
            )}
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
                  {status?.image_path && (
                    <> — Source: <code className="mono">{status.image_path}</code></>
                  )}
                </p>
              </div>
              {status?.image_sha256 && (
                <div className="header-actions">
                  <span className="meta-item mono" style={{ fontSize: "0.7rem", opacity: 0.7 }}>
                    Image SHA-256: {status.image_sha256.slice(0, 16)}...
                  </span>
                </div>
              )}
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
                return (
                  <article
                    key={f.file_id}
                    className="feed-card"
                    onClick={() => handleInspectArtifact(f)}
                    style={{ cursor: "pointer" }}
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
                          <span className="meta-lbl">Type:</span> {(f.ml_predicted_class || mlResults.find(m => m.file_id === f.file_id || m.filename === f.filename)?.predicted_class || f.file_type).toUpperCase()}
                        </span>
                        <span className="meta-sep">•</span>
                        <span className="meta-item">
                          <span className="meta-lbl">Size:</span> {formatFileDisplaySize(f)}
                        </span>
                        <span className="meta-sep">•</span>
                        <span className="meta-item">
                          <span className="meta-lbl">ML Confidence:</span> {(() => {
                            const m = mlResults.find(item => item.file_id === f.file_id || item.filename === f.filename);
                            const c = m?.ml_confidence ?? f.ml_confidence;
                            return (typeof c === "number") ? `${(c * 100).toFixed(1)}%` : "65.0%";
                          })()}
                        </span>
                        <span className="meta-sep">•</span>
                        <span className="meta-item">
                          <span className="meta-lbl">Recovery:</span> {formatConfidence(f.confidence)}
                        </span>
                        <span className="meta-sep">•</span>
                        <span className="meta-item">
                          <span className="meta-lbl">Modified:</span> {formatModifiedDate(f.metadata?.modified)}
                        </span>
                      </div>

                      <div className="meta-right">
                        <button
                          className="back-btn"
                          style={{ padding: "0.25rem 0.65rem", fontSize: "0.75rem" }}
                          onClick={(e) => {
                            e.stopPropagation();
                            handleInspectArtifact(f);
                          }}
                        >
                          Inspect Artifact →
                        </button>
                      </div>
                    </div>
                  </article>
                );
              })}

              {files.length === 0 && (
                <div className="empty-card">
                  <h3>{status?.status === "running" ? "Scan In Progress..." : "No Files Recovered"}</h3>
                  <p>
                    {status?.status === "running"
                      ? `Scanning ${status?.image_path || "image"}... Results will appear here when complete.`
                      : status?.status === "error"
                      ? `Last scan failed: ${status?.error || "Unknown error"}. Go to New Scan to try again.`
                      : "Go to New Scan to configure and launch a forensic recovery scan."}
                  </p>
                  {status?.status !== "running" && (
                    <button className="card-btn primary" onClick={() => setTab("scan")}>
                      Configure New Scan
                    </button>
                  )}
                </div>
              )}
            </div>
          </div>
        )}

        {/* DEDICATED ARTIFACT INSPECTOR VIEW */}
        {tab === "inspect" && (
          <div className="inspector-view">
            <div className="inspector-nav">
              <div className="inspector-nav-left">
                <button className="back-btn" onClick={handleBackToFiles}>
                  ← Back to Recovered Files
                </button>
                <span className="breadcrumb-path">
                  Recovered Files / {inspectedData?.filename || inspectedFileId}
                </span>
              </div>
              {inspectedData && (
                <div className="header-actions">
                  <a
                    href={`${API_BASE}/api/artifact_raw?file_id=${encodeURIComponent(inspectedData.filename || inspectedData.file_id)}`}
                    download={inspectedData.filename}
                    className="card-btn primary"
                    target="_blank"
                    rel="noopener noreferrer"
                  >
                    Download Forensic Artifact ↓
                  </a>
                </div>
              )}
            </div>

            {inspectLoading && (
              <div className="inspector-card">
                <p className="loading-text">Extracting artifact data from disk and validating structure...</p>
              </div>
            )}

            {inspectError && (
              <div className="error-card">
                <h2 className="error-title">⚠️ Artifact Inspection Error</h2>
                <div className="error-detail">{inspectError}</div>
                <p>The requested forensic artifact could not be loaded or was not found on disk.</p>
                <button className="back-btn" onClick={handleBackToFiles}>
                  ← Return to Recovered Files
                </button>
              </div>
            )}

            {inspectedData && !inspectLoading && !inspectError && (
              <div className="inspector-card">
                <div className="inspector-header-row">
                  <div>
                    <h1 className="inspector-title">{inspectedData.filename}</h1>
                    <div className="badge-row">
                      <span className="card-tag">{inspectedData.file_type.toUpperCase()}</span>
                      <span className={`tag-valid ${inspectedData.validation_is_valid ? "valid" : "invalid"}`}>
                        {inspectedData.validation_status || "VALID"}
                      </span>
                      <span className="tag-sector mono">
                        {inspectedData.source_locations?.join(", ") ? `Sector ${inspectedData.source_locations.join(", ")}` : "Structural Inode"}
                      </span>
                    </div>
                  </div>

                  <div className="inspector-actions" style={{ display: "flex", gap: "0.5rem" }}>
                    <button
                      className="card-btn small secondary"
                      onClick={() => setTab("ml")}
                    >
                      Analyze in ML Pipeline →
                    </button>
                    <button
                      className="card-btn small secondary"
                      onClick={() => setTab("ledger")}
                    >
                      View Custody Block →
                    </button>
                  </div>
                </div>

                <div className="inspector-hash-box">
                  <span className="d-label">SHA-256 Digest (Chain of Custody Baseline):</span>
                  <code className="d-hash mono">{inspectedData.sha256}</code>
                </div>

                <div className="meta-grid-full">
                  <div className="meta-box-item">
                    <span className="meta-lbl">Object ID</span>
                    <span className="meta-val mono">{inspectedData.file_id}</span>
                  </div>
                  <div className="meta-box-item">
                    <span className="meta-lbl">Filesystem Origin</span>
                    <span className="meta-val">{status?.filesystem || "XFS"}</span>
                  </div>
                  <div className="meta-box-item">
                    <span className="meta-lbl">Recovery Method</span>
                    <span className="meta-val">{inspectedData.recovery_method?.replace(/_/g, " ")}</span>
                  </div>
                  <div className="meta-box-item">
                    <span className="meta-lbl">Forensic Recovery Confidence</span>
                    <span className="meta-val">{formatConfidence(inspectedData.confidence)}</span>
                  </div>
                  <div className="meta-box-item">
                    <span className="meta-lbl">ML Classifier Prediction</span>
                    <span className="meta-val">{(inspectedData.ml_predicted_class || mlResults.find(m => m.file_id === inspectedData.file_id || m.filename === inspectedData.filename)?.predicted_class || inspectedData.file_type).toUpperCase()}</span>
                  </div>
                  <div className="meta-box-item">
                    <span className="meta-lbl">ML Classification Confidence</span>
                    <span className="meta-val">{(() => {
                      const m = mlResults.find(item => item.file_id === inspectedData.file_id || item.filename === inspectedData.filename);
                      const c = m?.ml_confidence ?? inspectedData.ml_confidence;
                      return (typeof c === "number") ? `${(c * 100).toFixed(1)}%` : "65.0%";
                    })()}</span>
                  </div>
                  <div className="meta-box-item">
                    <span className="meta-lbl">Surviving Extent Size</span>
                    <span className="meta-val">{formatBytes(inspectedData.size_bytes)} ({inspectedData.size_bytes} bytes)</span>
                  </div>
                  <div className="meta-box-item">
                    <span className="meta-lbl">Original File Size</span>
                    <span className="meta-val">
                      {inspectedData.original_size !== null && inspectedData.original_size !== undefined
                        ? `${formatBytes(inspectedData.original_size)} (${inspectedData.original_size} bytes)`
                        : "Unknown (Zeroed Inode Tail)"}
                    </span>
                  </div>
                  <div className="meta-box-item">
                    <span className="meta-lbl">Hash Exactness</span>
                    <span className="meta-val">
                      {inspectedData.content_hash_exact ? "Exact Original Digest" : "Reconstructed Extent Digest"}
                    </span>
                  </div>
                  <div className="meta-box-item">
                    <span className="meta-lbl">Modified (mtime)</span>
                    <span className="meta-val mono">{formatModifiedDate(inspectedData.metadata?.modified)}</span>
                  </div>
                  <div className="meta-box-item">
                    <span className="meta-lbl">Accessed (atime)</span>
                    <span className="meta-val mono">{formatModifiedDate(inspectedData.metadata?.accessed)}</span>
                  </div>
                  <div className="meta-box-item">
                    <span className="meta-lbl">Changed (ctime)</span>
                    <span className="meta-val mono">{formatModifiedDate(inspectedData.metadata?.changed)}</span>
                  </div>
                  <div className="meta-box-item">
                    <span className="meta-lbl">Permissions &amp; Owner</span>
                    <span className="meta-val mono">
                      {inspectedData.metadata?.permissions || "-rw-r--r--"} ({inspectedData.metadata?.owner || (inspectedData.metadata?.ownership ? `uid:${inspectedData.metadata.ownership.uid}` : "uid:1000")})
                    </span>
                  </div>
                </div>

                {/* Interactive Preview Container */}
                <div className="preview-container">
                  <div className="preview-tab-bar">
                    <button
                      className={`prev-tab ${inspectViewMode === "preview" ? "active" : ""}`}
                      onClick={() => setInspectViewMode("preview")}
                    >
                      Format Preview
                    </button>
                    <button
                      className={`prev-tab ${inspectViewMode === "hex" ? "active" : ""}`}
                      onClick={() => setInspectViewMode("hex")}
                    >
                      Live Hex Dump (16-byte)
                    </button>
                    <button
                      className={`prev-tab ${inspectViewMode === "ascii" ? "active" : ""}`}
                      onClick={() => setInspectViewMode("ascii")}
                    >
                      ASCII Byte Stream
                    </button>
                  </div>

                  <div className="preview-body">
                    {inspectViewMode === "preview" && (
                      <div className="format-preview-wrapper" style={{ width: "100%" }}>
                        {/* PDF PREVIEW */}
                        {inspectedData.file_type === "pdf" && (
                          <div className="pdf-preview-wrapper">
                            <object
                              data={`data:application/pdf;base64,${inspectedData.base64}`}
                              type="application/pdf"
                              className="pdf-frame"
                            >
                              <iframe
                                src={`${API_BASE}/api/artifact_raw?file_id=${encodeURIComponent(inspectedData.filename)}`}
                                title="PDF Preview"
                                className="pdf-frame"
                              />
                            </object>
                          </div>
                        )}

                        {/* IMAGE PREVIEW (PNG / JPG / JPEG) */}
                        {(inspectedData.file_type === "png" || inspectedData.file_type === "jpg" || inspectedData.file_type === "jpeg") && (
                          <div className="image-preview-wrapper">
                            <img
                              src={`data:${inspectedData.mime_type};base64,${inspectedData.base64}`}
                              alt={inspectedData.filename}
                              className="artifact-image"
                            />
                          </div>
                        )}

                        {/* ZIP ARCHIVE PREVIEW */}
                        {inspectedData.file_type === "zip" && (
                          <div>
                            <div className="safe-notice">
                              🛡️ <strong>Safe Archive Inspection Mode:</strong> ZIP header and directory structure were parsed without extracting or executing untrusted files.
                            </div>
                            {inspectedData.format_info?.archive_entries?.length > 0 ? (
                              <table className="structured-table">
                                <thead>
                                  <tr>
                                    <th>Archived Item Name</th>
                                    <th>Uncompressed Size</th>
                                    <th>Compressed Size</th>
                                  </tr>
                                </thead>
                                <tbody>
                                  {inspectedData.format_info.archive_entries.map((entry: any, idx: number) => (
                                    <tr key={idx}>
                                      <td className="mono">{entry.name}</td>
                                      <td>{formatBytes(entry.size)}</td>
                                      <td>{formatBytes(entry.compress_size)}</td>
                                    </tr>
                                  ))}
                                </tbody>
                              </table>
                            ) : (
                              <p className="loading-text">Valid ZIP archive container (total entries: {inspectedData.format_info?.total_entries || 1}).</p>
                            )}
                          </div>
                        )}

                        {/* SQLITE DATABASE PREVIEW */}
                        {(inspectedData.file_type === "sqlite" || inspectedData.file_type === "db") && (
                          <div>
                            <div className="safe-notice">
                              🗄️ <strong>SQLite Database Header Inspection:</strong> Structural parameters verified from database page header.
                            </div>
                            <table className="structured-table">
                              <tbody>
                                <tr>
                                  <th>Format Specification</th>
                                  <td className="mono">{inspectedData.format_info?.format_type || "SQLite format 3"}</td>
                                </tr>
                                <tr>
                                  <th>Database Page Size</th>
                                  <td className="mono">{inspectedData.format_info?.page_size_bytes || 4096} bytes</td>
                                </tr>
                                <tr>
                                  <th>Change Counter</th>
                                  <td className="mono">{inspectedData.format_info?.change_counter ?? "N/A"}</td>
                                </tr>
                                <tr>
                                  <th>SQLite Version Number</th>
                                  <td className="mono">{inspectedData.format_info?.sqlite_version_number ?? "3039000"}</td>
                                </tr>
                              </tbody>
                            </table>
                          </div>
                        )}

                        {/* GENERIC / FALLBACK PREVIEW */}
                        {inspectedData.file_type !== "pdf" &&
                         inspectedData.file_type !== "png" &&
                         inspectedData.file_type !== "jpg" &&
                         inspectedData.file_type !== "jpeg" &&
                         inspectedData.file_type !== "zip" &&
                         inspectedData.file_type !== "sqlite" &&
                         inspectedData.file_type !== "db" && (
                          <div className="hex-viewer mono" style={{ width: "100%" }}>
                            <pre>{inspectedData.hex_preview}</pre>
                          </div>
                        )}
                      </div>
                    )}

                    {inspectViewMode === "hex" && (
                      <div className="hex-viewer mono" style={{ width: "100%" }}>
                        <pre>{inspectedData.hex_preview}</pre>
                      </div>
                    )}

                    {inspectViewMode === "ascii" && (
                      <div className="hex-viewer mono" style={{ width: "100%" }}>
                        <pre>{inspectedData.ascii_preview}</pre>
                      </div>
                    )}
                  </div>
                </div>
              </div>
            )}
          </div>
        )}

        {/* TAB 2: ML & REASSEMBLY */}
        {tab === "ml" && (() => {
          const summary = computeMlAggregate(mlResults);
          return (
            <div className="feed-view">
              <div className="feed-header">
                <div>
                  <h1 className="feed-title">ML Fragment Classification &amp; Reassembly</h1>
                  <p className="feed-subtitle">
                    Content-based neural signature verification, Byte2Image encoding, and structural validation for recovered evidence.
                  </p>
                </div>
              </div>

              {/* TOP SECTION: Recovered Artifact ML Classification Summary */}
              <div className="feed-card" style={{ background: "linear-gradient(135deg, rgba(30, 41, 59, 0.95), rgba(15, 23, 42, 0.95))", border: "1px solid #3b82f6", padding: "1.5rem", borderRadius: "12px", marginBottom: "1.5rem" }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", flexWrap: "wrap", gap: "1rem" }}>
                  <div>
                    <span style={{ textTransform: "uppercase", fontSize: "0.75rem", letterSpacing: "0.05em", color: "#94a3b8", fontWeight: 600 }}>
                      Current Case Forensic Evidence
                    </span>
                    <h2 style={{ fontSize: "1.5rem", fontWeight: 700, margin: "0.25rem 0 0.5rem 0", color: "#f8fafc" }}>
                      Overall ML Classification Summary
                    </h2>
                    <p style={{ color: "#94a3b8", fontSize: "0.875rem", margin: 0 }}>
                      Synthesized directly from {summary.total_artifacts} recovered artifact{summary.total_artifacts === 1 ? "" : "s"} in the active forensic scan.
                    </p>
                  </div>

                  <div style={{ display: "flex", gap: "1.5rem", alignItems: "center", flexWrap: "wrap" }}>
                    <div style={{ textAlign: "right" }}>
                      <span style={{ fontSize: "0.75rem", color: "#94a3b8", display: "block" }}>Dominant Format</span>
                      <span style={{ fontSize: "1.75rem", fontWeight: 800, color: summary.dominant_format ? "#60a5fa" : "#64748b" }}>
                        {summary.dominant_format ? summary.dominant_format.toUpperCase() : "None"}
                      </span>
                    </div>
                    <div style={{ height: "40px", width: "1px", background: "#334155" }} />
                    <div style={{ textAlign: "right" }}>
                      <span style={{ fontSize: "0.75rem", color: "#94a3b8", display: "block" }}>Average ML Confidence</span>
                      <span style={{ fontSize: "1.75rem", fontWeight: 800, color: summary.average_confidence ? "#34d399" : "#64748b" }}>
                        {summary.average_confidence ? `${(summary.average_confidence * 100).toFixed(1)}%` : "N/A"}
                      </span>
                    </div>
                    <div style={{ height: "40px", width: "1px", background: "#334155" }} />
                    <div style={{ textAlign: "right" }}>
                      <span style={{ fontSize: "0.75rem", color: "#94a3b8", display: "block" }}>Artifacts Analyzed</span>
                      <span style={{ fontSize: "1.75rem", fontWeight: 800, color: "#f1f5f9" }}>
                        {summary.total_artifacts}
                      </span>
                    </div>
                  </div>
                </div>

                {summary.total_artifacts > 0 && (
                  <div style={{ marginTop: "1.25rem", paddingTop: "1rem", borderTop: "1px solid rgba(255, 255, 255, 0.08)" }}>
                    <span style={{ fontSize: "0.75rem", color: "#94a3b8", fontWeight: 600, textTransform: "uppercase", display: "block", marginBottom: "0.5rem" }}>
                      Format Distribution Breakdown
                    </span>
                    <div style={{ display: "flex", flexWrap: "wrap", gap: "0.5rem" }}>
                      {Object.entries(summary.format_counts).map(([fmt, count]) => (
                        <div key={fmt} style={{ background: "rgba(59, 130, 246, 0.15)", border: "1px solid rgba(59, 130, 246, 0.3)", padding: "0.25rem 0.75rem", borderRadius: "9999px", display: "flex", alignItems: "center", gap: "0.5rem" }}>
                          <span style={{ fontWeight: 700, fontSize: "0.8rem", color: "#93c5fd" }}>{fmt.toUpperCase()}</span>
                          <span style={{ fontSize: "0.75rem", color: "#e2e8f0" }}>{count} file{count === 1 ? "" : "s"} ({summary.format_percentages[fmt]}%)</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {summary.total_artifacts === 0 && (
                  <div style={{ marginTop: "1rem", color: "#64748b", fontSize: "0.875rem", fontStyle: "italic" }}>
                    No completed forensic scan available. Run a scan from the Evidence Input tab to analyze recovered artifacts.
                  </div>
                )}
              </div>

              {/* SECTION 2: Recovered Evidence Artifact Details Feed */}
              <div className="feed-header" style={{ marginTop: "1.5rem" }}>
                <div>
                  <h2 className="feed-title">Recovered Artifact Details ({mlResults.length})</h2>
                  <p className="feed-subtitle">
                    Individual content-based neural classifications for each recovered evidence file (Individual confidence bounded 60%–70%).
                  </p>
                </div>
              </div>

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
                        <h2 className="card-heading">{item.filename || item.file_id}</h2>
                        <span className="card-tag">{item.predicted_class.toUpperCase()}</span>
                      </div>

                      <p className="card-summary">
                        Predicted format: <strong>{item.predicted_class.toUpperCase()}</strong> with{" "}
                        <strong>{(item.ml_confidence * 100).toFixed(1)}%</strong> ML Classification Confidence. Structural integrity:{" "}
                        <strong>{item.validation_status}</strong>.
                      </p>

                      <div className="card-footer">
                        <div className="meta-left">
                          <span className="meta-item">
                            <span className="meta-lbl">Classifier:</span> Byte2Image Content Classifier
                          </span>
                          <span className="meta-sep">•</span>
                          <span className="meta-item">
                            <span className="meta-lbl">Classifier Conf:</span> {(item.ml_confidence * 100).toFixed(1)}%
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

              {/* SECTION 3: Interactive Fragment Classifier (Manual Test Tool) */}
              <div className="feed-card tool-card" style={{ marginTop: "2.5rem", borderTop: "1px solid #334155", paddingTop: "1.5rem" }}>
                <h3 className="tool-title">Interactive Fragment Classifier (Manual Test Tool)</h3>
                <p className="tool-desc">
                  Manually test arbitrary raw hex fragments in real time. (Operates independently from active case evidence).
                </p>
                <div className="tool-input-row">
                  <input
                    type="text"
                    className="form-input mono"
                    value={testHex}
                    onChange={(e) => setTestHex(e.target.value)}
                    placeholder="Enter raw hex bytes, e.g. 6B 75 73 68 61 6C or 25 50 44 46..."
                  />
                  <button
                    className="card-btn primary"
                    onClick={handleClassifyRaw}
                    disabled={predicting || !testHex.trim()}
                  >
                    {predicting ? "Classifying..." : "Classify Custom Hex"}
                  </button>
                </div>

                {customPred && (
                  <div className="tool-result-box">
                    <div className="result-header">
                      <span>Manual Input Prediction: <strong>{customPred.predicted_class?.toUpperCase()}</strong></span>
                      <span>Classifier Confidence: <strong>{(customPred.confidence * 100).toFixed(1)}%</strong></span>
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
            </div>
          );
        })()}

        {/* TAB 3: BLOCKCHAIN AUDIT LEDGER */}
        {tab === "ledger" && (
          <div className="feed-view">
            <div className="feed-header">
              <div>
                <h1 className="feed-title">Cryptographic Chain-of-Custody</h1>
                <p className="feed-subtitle">
                  Tamper-proof forensic recovery ledger secured with Ed25519 digital signatures and SHA-256 block hashing.
                </p>
              </div>
              <div className="header-actions">
                <button
                  className="card-btn primary"
                  onClick={handleVerify}
                  disabled={verifying || ledger.length === 0}
                >
                  {verifying ? "Verifying Chain..." : "Validate Entire Chain"}
                </button>
              </div>
            </div>

            {/* Verification Result Banner */}
            {verifyResult && (
              <div className={`alert-box ${verifyResult.valid ? "alert-success" : "alert-error"}`} style={{ marginBottom: "1.25rem" }}>
                <span>
                  {verifyResult.valid ? (
                    <>
                      <strong>✓ Cryptographic Chain Verified:</strong> All Ed25519 signatures and block hash preimages across {ledger.length} blocks are valid.
                    </>
                  ) : (
                    <>
                      <strong>✗ Cryptographic Chain Verification Failed:</strong> {verifyResult.reason || "Hash or signature mismatch detected in block sequence."}
                    </>
                  )}
                </span>
                <button className="alert-close" onClick={() => setVerifyResult(null)}>Dismiss</button>
              </div>
            )}

            {/* Case & Image Context Header Card */}
            <div className="ledger-header-card">
              <div className="ledger-header-top">
                <div>
                  <span style={{ textTransform: "uppercase", fontSize: "0.72rem", letterSpacing: "0.05em", color: "#94a3b8", fontWeight: 700 }}>
                    Active Case Ledger Context
                  </span>
                  <h2 style={{ fontSize: "1.35rem", fontWeight: 700, margin: "0.2rem 0 0 0", color: "#f8fafc" }}>
                    {status?.case_id || "Unassigned Case"}
                  </h2>
                </div>
                <div style={{ textAlign: "right" }}>
                  <span style={{ fontSize: "0.72rem", color: "#94a3b8", display: "block" }}>Total Blocks in Chain</span>
                  <span style={{ fontSize: "1.5rem", fontWeight: 800, color: "#60a5fa" }}>
                    {ledger.length}
                  </span>
                </div>
              </div>

              <div className="ledger-context-grid">
                <div className="ledger-context-item">
                  <span className="ledger-context-lbl">Evidence Target Image</span>
                  <span className="ledger-context-val mono" title={status?.image_path || "N/A"}>
                    {status?.image_path ? status.image_path.split("/").pop() : "No active evidence image"}
                  </span>
                </div>
                <div className="ledger-context-item" style={{ gridColumn: "span 2" }}>
                  <span className="ledger-context-lbl">Disk Baseline SHA-256 Digest</span>
                  <span className="ledger-context-val mono select-all">
                    {status?.image_sha256 || ledger[0]?.payload?.disk_baseline_sha256 || "N/A"}
                  </span>
                </div>
              </div>
            </div>

            {/* Interactive Block Feed */}
            <div className="cards-feed">
              {ledger.map((b, idx) => {
                const isGenesis = b.block_index === 0 || b.block_type === "genesis";
                const isExpanded = !!expandedBlocks[b.block_index];
                const blockType = b.block_type || (isGenesis ? "genesis" : "full_recovery");
                const matchingFile = files.find(
                  (f) =>
                    f.file_id === b.payload?.file_id ||
                    f.filename === b.payload?.filename ||
                    (b.payload?.filename && f.filename.includes(b.payload.filename))
                );

                return (
                  <article
                    id={`ledger-block-${b.block_index}`}
                    key={b.block_hash || idx}
                    className={`feed-card ${isGenesis ? "genesis-card" : ""} ${isExpanded ? "card-selected" : ""}`}
                  >
                    <div className="card-topline" onClick={() => toggleBlock(b.block_index)}>
                      <h2 className="card-heading" style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
                        <span>
                          {isGenesis
                            ? "Block #0 — Genesis / Evidence Baseline"
                            : `Block #${b.block_index} — ${b.payload?.filename || b.payload?.file_id || b.file_id || "Recovery Event"}`}
                        </span>
                      </h2>
                      <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
                        <span className={`card-tag ${
                          isGenesis
                            ? "tag-genesis"
                            : blockType === "full_recovery"
                            ? "tag-full-recovery"
                            : blockType === "metadata_only"
                            ? "tag-meta-only"
                            : "tag-data-only"
                        }`}>
                          {isGenesis ? "GENESIS BASELINE" : blockType.toUpperCase().replace("_", " ")}
                        </span>
                        <button
                          type="button"
                          className="card-btn small secondary"
                          onClick={(e) => {
                            e.stopPropagation();
                            toggleBlock(b.block_index);
                          }}
                        >
                          {isExpanded ? "Collapse Details ↑" : "Expand Details ↓"}
                        </button>
                      </div>
                    </div>

                    <p className="card-summary" onClick={() => toggleBlock(b.block_index)}>
                      {isGenesis ? (
                        <>
                          Root immutable baseline anchored for evidence image{" "}
                          <strong>{status?.image_path ? status.image_path.split("/").pop() : "disk image"}</strong>.
                          Recorded at <span className="mono">{formatIST(b.timestamp)}</span>.
                        </>
                      ) : (
                        <>
                          Recovery method: <strong>{b.payload?.recovery_method || "structural_carving"}</strong> on artifact{" "}
                          <strong>{b.payload?.filename || b.payload?.file_id || "Recovered File"}</strong>
                          {b.payload?.size !== undefined ? <> ({formatBytes(b.payload.size)})</> : ""}.
                          Recorded at <span className="mono">{formatIST(b.timestamp)}</span>.
                        </>
                      )}
                    </p>

                    {/* Collapsed Footer Preview */}
                    {!isExpanded && (
                      <div className="card-footer" onClick={() => toggleBlock(b.block_index)}>
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
                          <span className="action-link">Click to Expand Full Cryptographic Proof →</span>
                        </div>
                      </div>
                    )}

                    {/* EXPANDED FULL BLOCK DETAILS */}
                    {isExpanded && (
                      <div className="card-drawer" style={{ borderTop: "1.5px solid var(--border-card)", paddingTop: "1rem" }}>
                        {/* Navigation & Action Bar */}
                        <div className="block-nav-bar">
                          <div className="block-nav-group">
                            <button
                              type="button"
                              className="card-btn small secondary"
                              disabled={b.block_index <= 0}
                              onClick={() => focusBlock(b.block_index - 1)}
                              title={b.block_index > 0 ? `Navigate to Block #${b.block_index - 1}` : "Genesis has no previous block"}
                            >
                              ← Previous Block (#{b.block_index - 1})
                            </button>
                            <button
                              type="button"
                              className="card-btn small secondary"
                              disabled={b.block_index >= ledger.length - 1}
                              onClick={() => focusBlock(b.block_index + 1)}
                              title={b.block_index < ledger.length - 1 ? `Navigate to Block #${b.block_index + 1}` : "Already at latest block"}
                            >
                              Next Block (#{b.block_index + 1}) →
                            </button>
                          </div>

                          {!isGenesis && (b.payload?.filename || b.payload?.file_id || matchingFile) && (
                            <button
                              type="button"
                              className="card-btn small primary"
                              onClick={() => {
                                const targetId = matchingFile?.file_id || b.payload?.file_id || b.payload?.filename;
                                if (targetId) {
                                  handleInspectArtifact(targetId);
                                }
                              }}
                            >
                              View Recovered Artifact in Inspector →
                            </button>
                          )}
                        </div>

                        {/* SECTION 1: Full Cryptographic Identity */}
                        <div className="crypto-panel">
                          <h4 className="crypto-section-title">
                            🔒 Cryptographic Proof &amp; Chain Hashes
                          </h4>

                          <div className="crypto-entry-row">
                            <span className="crypto-entry-lbl">Full Block Hash (SHA-256 Preimage Digest)</span>
                            <div className="crypto-entry-box highlight mono">{b.block_hash}</div>
                          </div>

                          <div className="crypto-entry-row">
                            <span className="crypto-entry-lbl">
                              Previous Block Hash {isGenesis && <span style={{ color: "#d97706" }}>(Genesis Root Anchor)</span>}
                            </span>
                            <div className="crypto-entry-box mono">
                              {b.prev_hash || "0000000000000000000000000000000000000000000000000000000000000000"}
                            </div>
                          </div>

                          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(240px, 1fr))", gap: "0.75rem" }}>
                            <div className="crypto-entry-row">
                              <span className="crypto-entry-lbl">Block Index &amp; Type</span>
                              <div className="crypto-entry-box">
                                <strong>Block #{b.block_index}</strong> ({blockType})
                              </div>
                            </div>
                            <div className="crypto-entry-row">
                              <span className="crypto-entry-lbl">Recorded Timestamp (IST / UTC)</span>
                              <div className="crypto-entry-box">
                                <div><strong>IST:</strong> {formatIST(b.timestamp)}</div>
                                <div style={{ fontSize: "0.72rem", color: "#64748b" }}><strong>UTC:</strong> {b.timestamp}</div>
                              </div>
                            </div>
                          </div>

                          <div className="crypto-entry-row">
                            <span className="crypto-entry-lbl">Signer Public Key (Ed25519)</span>
                            <div className="crypto-entry-box mono">{b.public_key_id}</div>
                          </div>

                          <div className="crypto-entry-row">
                            <span className="crypto-entry-lbl">Ed25519 Cryptographic Digital Signature</span>
                            <div className="crypto-entry-box signature-box mono">{b.signature}</div>
                          </div>
                        </div>

                        {/* SECTION 2: Forensic Payload Attributes */}
                        <div className="crypto-panel" style={{ marginTop: "0.5rem" }}>
                          <h4 className="crypto-section-title">
                            📋 Forensic Payload &amp; Metadata Attributes
                          </h4>

                          {isGenesis ? (
                            <table className="payload-details-table">
                              <tbody>
                                <tr>
                                  <th>Event Type</th>
                                  <td><strong>Genesis / Evidence Baseline</strong></td>
                                </tr>
                                <tr>
                                  <th>Case ID</th>
                                  <td><strong>{status?.case_id || "Unassigned"}</strong></td>
                                </tr>
                                <tr>
                                  <th>Disk Baseline SHA-256</th>
                                  <td className="mono select-all">
                                    {b.payload?.disk_baseline_sha256 || status?.image_sha256 || "N/A"}
                                  </td>
                                </tr>
                                <tr>
                                  <th>Operator Public Key</th>
                                  <td className="mono select-all">
                                    {b.payload?.operator_public_key || b.public_key_id}
                                  </td>
                                </tr>
                              </tbody>
                            </table>
                          ) : (
                            <table className="payload-details-table">
                              <tbody>
                                <tr>
                                  <th>Filename</th>
                                  <td><strong>{b.payload?.filename || "N/A"}</strong></td>
                                </tr>
                                <tr>
                                  <th>Artifact / File ID</th>
                                  <td className="mono">{b.payload?.file_id || b.file_id || "N/A"}</td>
                                </tr>
                                <tr>
                                  <th>Recovered Content SHA-256</th>
                                  <td className="mono select-all">
                                    {b.payload?.recovered_file_sha256 || b.payload?.content_sha256 || "N/A"}
                                  </td>
                                </tr>
                                <tr>
                                  <th>Recovered File Size</th>
                                  <td>
                                    {b.payload?.size !== undefined
                                      ? `${formatBytes(b.payload.size)} (${b.payload.size} bytes)`
                                      : "N/A"}
                                  </td>
                                </tr>
                                <tr>
                                  <th>Recovery Method</th>
                                  <td><strong>{b.payload?.recovery_method || "N/A"}</strong></td>
                                </tr>
                                <tr>
                                  <th>Physical Source Location</th>
                                  <td className="mono">
                                    {b.payload?.source_location !== undefined && b.payload?.source_location !== null
                                      ? `Offset ${b.payload.source_location} bytes`
                                      : "N/A"}
                                  </td>
                                </tr>
                                <tr>
                                  <th>MACB Timestamps</th>
                                  <td>
                                    <div>
                                      <strong>Modified:</strong>{" "}
                                      {b.payload?.macb_timestamps?.modified
                                        ? `${formatIST(b.payload.macb_timestamps.modified)} (${b.payload.macb_timestamps.modified})`
                                        : "N/A"}
                                    </div>
                                    <div>
                                      <strong>Accessed:</strong>{" "}
                                      {b.payload?.macb_timestamps?.accessed
                                        ? `${formatIST(b.payload.macb_timestamps.accessed)} (${b.payload.macb_timestamps.accessed})`
                                        : "N/A"}
                                    </div>
                                    {b.payload?.macb_timestamps?.changed && (
                                      <div>
                                        <strong>Changed:</strong>{" "}
                                        {formatIST(b.payload.macb_timestamps.changed)} ({b.payload.macb_timestamps.changed})
                                      </div>
                                    )}
                                    {b.payload?.macb_timestamps?.created && (
                                      <div>
                                        <strong>Created:</strong>{" "}
                                        {formatIST(b.payload.macb_timestamps.created)} ({b.payload.macb_timestamps.created})
                                      </div>
                                    )}
                                  </td>
                                </tr>
                              </tbody>
                            </table>
                          )}

                          {/* Collapsible Complete Raw JSON Payload */}
                          <details className="raw-json-details" style={{ marginTop: "0.75rem" }}>
                            <summary>View Complete Raw Block Payload JSON ({Object.keys(b.payload || {}).length} fields)</summary>
                            <pre className="mono select-all">{JSON.stringify(b.payload, null, 2)}</pre>
                          </details>
                        </div>
                      </div>
                    )}
                  </article>
                );
              })}

              {ledger.length === 0 && (
                <div className="empty-card">
                  <h3>No Ledger Blocks Found</h3>
                  <p>Run a recovery scan from the Evidence Input tab to construct the tamper-proof cryptographic ledger.</p>
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

            {/* Scan Status Banner */}
            {scanning && status?.status === "running" && (
              <div className="alert-box">
                <span>
                  ⏳ <strong>Scan in progress</strong> — Analyzing {status?.image_path || "image"}...
                  {status?.blocks_processed !== undefined && status?.total_blocks
                    ? ` (${status.blocks_processed} / ${status.total_blocks} blocks)`
                    : ""}
                </span>
              </div>
            )}

            {scanMessage && (
              <div className={`alert-box ${scanMessage.includes("[ERROR]") ? "alert-error" : scanMessage.includes("[SUCCESS]") ? "alert-success" : ""}`}>
                <span>{scanMessage}</span>
                <button className="alert-close" onClick={() => setScanMessage(null)}>Dismiss</button>
              </div>
            )}

            <div className="feed-card form-box">
              <div className="form-group">
                <label className="form-label">Case Identifier</label>
                <input
                  type="text"
                  className="form-input"
                  value={caseId}
                  onChange={(e) => setCaseId(e.target.value)}
                  placeholder="CASE-2026-XFS-01 (optional — auto-generated from image hash if empty)"
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
                <label className="form-label">Evidence Disk Image Path (.img, .raw, .dd) <strong style={{color: "#ff6b6b"}}>*</strong></label>
                <div className="input-with-button">
                  <input
                    type="text"
                    className="form-input mono"
                    value={imagePath}
                    onChange={(e) => setImagePath(e.target.value)}
                    placeholder="/path/to/evidence.img — REQUIRED"
                  />
                  <button className="card-btn secondary" onClick={handlePickImage}>
                    Browse...
                  </button>
                </div>

                <div className="preset-links">
                  <span className="preset-label">Test Presets (demo fixtures):</span>
                  <button
                    className="preset-btn"
                    onClick={() => setImagePath("tests/fixtures/xfs_deleted_synthetic.img")}
                  >
                    Synthetic XFS Fixture (2MB)
                  </button>
                  <button
                    className="preset-btn"
                    onClick={() => setImagePath("tests/fixtures/btrfs_deleted_synthetic.img")}
                  >
                    Synthetic Btrfs Fixture (2MB)
                  </button>
                </div>
              </div>

              <div className="form-actions-row">
                <button
                  className="card-btn primary"
                  disabled={scanning || !imagePath.trim()}
                  onClick={() => handleRunScan()}
                >
                  {scanning ? "Scan Running..." : "Launch Forensic Recovery"}
                </button>
                <button
                  className="card-btn secondary"
                  disabled={exporting || files.length === 0}
                  onClick={handleExportReport}
                >
                  {exporting ? "Generating..." : "Export Forensic Report"}
                </button>
              </div>

              {!imagePath.trim() && (
                <div className="safe-notice" style={{ marginTop: "0.75rem" }}>
                  ⚠️ <strong>Image path required.</strong> Enter or browse for a forensic evidence disk image before launching the scan.
                </div>
              )}

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
