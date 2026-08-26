import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { open } from "@tauri-apps/plugin-dialog";
import "./App.css";

type FileMetadata = {
  modified: string | null;
  accessed: string | null;
  changed: string | null;
  birth: string | null;
  permissions: string | null;
  owner: string | null;
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
};

type CaseStatus = {
  case_id: string;
  filesystem: string;
  status: string;
  files_recovered: number;
  fragments_found: number;
  blocks_processed: number;
  total_blocks: number;
};

type RecoveryEventPayload = {
  event_id: string;
  action: string;
  recovery_method: string;
  file_id: string | null;
  source_location: string | null;
  confidence: number | null;
  file_sha256: string | null;
};

type LedgerBlock = {
  block_index: number;
  timestamp: string;
  payload: RecoveryEventPayload;
  prev_hash: string | null;
  block_hash: string;
  signature: string;
  public_key_id: string;
};

function confidencePillClass(c: number | null) {
  if (c === null) return "pill none";
  if (c >= 90) return "pill high";
  if (c >= 70) return "pill mid";
  return "pill low";
}

function App() {
  const [tab, setTab] = useState<"setup" | "overview" | "ledger">("setup");

  const [files, setFiles] = useState<RecoveredFile[]>([]);
  const [selected, setSelected] = useState<RecoveredFile | null>(null);
  const [status, setStatus] = useState<CaseStatus | null>(null);

  const [ledger, setLedger] = useState<LedgerBlock[]>([]);
  const [verifyResult, setVerifyResult] = useState<boolean | null>(null);
  const [verifying, setVerifying] = useState(false);
  const [caseId, setCaseId] = useState("");
  const [investigator, setInvestigator] = useState("");
  const [imagePath, setImagePath] = useState<string | null>(null);

  const [reportPath, setReportPath] = useState<string | null>(null);
  const [exporting, setExporting] = useState(false);

  useEffect(() => {
    invoke<RecoveredFile[]>("list_recovered_files").then(setFiles);
    invoke<CaseStatus>("get_case_status").then(setStatus);
    invoke<LedgerBlock[]>("get_ledger").then(setLedger);
  }, []);

  const handleVerify = async () => {
    setVerifying(true);
    setVerifyResult(null);
    const result = await invoke<boolean>("verify_chain");
    setVerifyResult(result);
    setVerifying(false);
  };

  const handlePickImage = async () => {
    const selected = await open({
      multiple: false,
      directory: false,
      title: "Select forensic image",
    });
    if (selected) setImagePath(selected as string);
  };

  const handleExportReport = async () => {
    setExporting(true);
    setReportPath(null);
    const path = await invoke<string>("export_report", {
      caseId: caseId,
      investigator: investigator,
    });
    setReportPath(path);
    setExporting(false);
  };

  const progressPct = status
    ? Math.round((status.blocks_processed / status.total_blocks) * 100)
    : 0;

  return (
    <div className="app">
      <div className="app-header">
        <span className="brand">FirSeFile</span>
        <button
          className={`tab-btn ${tab === "setup" ? "active" : ""}`}
          onClick={() => setTab("setup")}
        >
          Case Setup
        </button>
        <button
          className={`tab-btn ${tab === "overview" ? "active" : ""}`}
          onClick={() => setTab("overview")}
        >
          Overview
        </button>
        <button
          className={`tab-btn ${tab === "ledger" ? "active" : ""}`}
          onClick={() => setTab("ledger")}
        >
          Ledger
        </button>
      </div>

      <div className="page">
        {tab === "setup" && (
          <div className="form-card">
            <p className="eyebrow">New Session</p>
            <h2>Case Setup</h2>

            <div className="field">
              <label>Case ID</label>
              <input value={caseId} onChange={(e) => setCaseId(e.target.value)} />
            </div>

            <div className="field">
              <label>Investigator</label>
              <input value={investigator} onChange={(e) => setInvestigator(e.target.value)} />
            </div>

            <div className="field">
              <label>Forensic Image</label>
              <button className="btn btn-secondary" onClick={handlePickImage}>
                Select Forensic Image
              </button>
              <p className="image-path">
                {imagePath ? imagePath : "No image selected"}
              </p>
            </div>

            <div className="btn-row">
              <button
                className="btn btn-primary"
                disabled={!caseId || !imagePath}
                onClick={() => setTab("overview")}
              >
                Start Recovery Session
              </button>
              <button
                className="btn btn-secondary"
                disabled={!caseId || exporting}
                onClick={handleExportReport}
              >
                {exporting ? "Exporting..." : "Export Report"}
              </button>
            </div>
            {reportPath && <p className="result-msg">Report saved to: {reportPath}</p>}
          </div>
        )}

        {tab === "overview" && (
          <>
            <p className="eyebrow">Session Status</p>
            <h2>Recovery Dashboard</h2>

            {status ? (
              <div className="status-bar">
                <div className="status-cell">
                  <span className="label">Case</span>
                  <span className="value mono">{status.case_id}</span>
                </div>
                <div className="status-cell">
                  <span className="label">Filesystem</span>
                  <span className="value">{status.filesystem}</span>
                </div>
                <div className="status-cell">
                  <span className="label">Status</span>
                  <span className="value">{status.status}</span>
                </div>
                <div className="status-cell">
                  <span className="label">Files Recovered</span>
                  <span className="value">{status.files_recovered}</span>
                </div>
                <div className="status-cell">
                  <span className="label">Fragments Found</span>
                  <span className="value">{status.fragments_found}</span>
                </div>
                <div className="status-cell" style={{ minWidth: "180px" }}>
                  <span className="label">Progress</span>
                  <span className="value">{progressPct}%</span>
                  <div className="progress-track">
                    <div className="progress-fill" style={{ width: `${progressPct}%` }} />
                  </div>
                </div>
              </div>
            ) : (
              <p className="empty-state">Loading status...</p>
            )}

            <div className="split">
              <div className="main">
                <h3>Recovered Files</h3>
                <div style = {{overflow: "auto"}}>
                  <table className="evidence-table">
                    <thead>
                      <tr>
                        <th>Filename</th>
                        <th>Type</th>
                        <th>Size</th>
                        <th>Filesystem</th>
                        <th>Method</th>
                        <th>Confidence</th>
                      </tr>
                    </thead>
                    <tbody>
                      {files.map((f) => (
                        <tr
                          key={f.file_id}
                          onClick={() => setSelected(f)}
                          className={selected?.file_id === f.file_id ? "selected" : ""}
                        >
                          <td>{f.filename}</td>
                          <td>{f.file_type}</td>
                          <td className="mono-cell">{f.size.toLocaleString()} B</td>
                          <td>{f.filesystem}</td>
                          <td className="mono-cell">{f.recovery_method}</td>
                          <td>
                            <span className={confidencePillClass(f.confidence)}>
                              {f.confidence !== null ? `${f.confidence}%` : "—"}
                            </span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>

              <div className="side">
                <h3>Details</h3>
                {selected ? (
                  <div className="detail-card">
                    <div className="detail-row"><span className="k">File ID</span><span className="v">{selected.file_id}</span></div>
                    <div className="detail-row"><span className="k">SHA-256</span><span className="v">{selected.sha256 ?? "—"}</span></div>
                    <div className="detail-row"><span className="k">Source</span><span className="v">{selected.source_locations.join(", ")}</span></div>
                    <div className="detail-row"><span className="k">Modified</span><span className="v">{selected.metadata.modified ?? "—"}</span></div>
                    <div className="detail-row"><span className="k">Permissions</span><span className="v">{selected.metadata.permissions ?? "—"}</span></div>
                    <div className="detail-row"><span className="k">Owner</span><span className="v">{selected.metadata.owner ?? "—"}</span></div>
                  </div>
                ) : (
                  <p className="empty-state">Click a row to see details</p>
                )}
              </div>
            </div>
          </>
        )}

        {tab === "ledger" && (
          <>
            <p className="eyebrow">Chain of Custody</p>
            <h2>Recovery Ledger</h2>

            <div className="btn-row" style={{ marginTop: 0, marginBottom: "1.25rem" }}>
              <button className="btn btn-primary" onClick={handleVerify} disabled={verifying}>
                {verifying ? "Verifying..." : "Verify Chain"}
              </button>
            </div>

            {verifyResult !== null && (
              <div className={`verify-result ${verifyResult ? "ok" : "fail"}`}>
                {verifyResult ? "✓ Chain Verified" : "✗ Verification Failed"}
              </div>
            )}

            <div className="ledger-chain">
              {ledger.map((b) => (
                <div className="ledger-block" key={b.block_index}>
                  <div className="ledger-block-head">
                    <span className="ledger-block-id">BLOCK #{String(b.block_index).padStart(3, "0")}</span>
                    <span className="ledger-block-time">{b.timestamp}</span>
                  </div>
                  <div className="ledger-block-body">
                    <div>Method <div className="v">{b.payload.recovery_method}</div></div>
                    <div>File <div className="v">{b.payload.file_id ?? "—"}</div></div>
                    <div>Source <div className="v">{b.payload.source_location ?? "—"}</div></div>
                    <div>Hash <div className="v">{b.block_hash}</div></div>
                  </div>
                </div>
              ))}
            </div>
          </>
        )}
      </div>
    </div>
  );
}

export default App;
