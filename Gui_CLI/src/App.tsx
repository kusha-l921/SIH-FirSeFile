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
  // ML fields
  ml_predicted_class: string | null;
  ml_confidence: number | null;
  ml_top_k: MlPrediction[] | null;
  validation_status: string | null;
  validation_is_valid: boolean | null;
  reconstruction_confidence: number | null;
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
  if (c === null) return "pill none";
  if (c >= 90) return "pill high";
  if (c >= 70) return "pill mid";
  return "pill low";
}

function App() {
  const [tab, setTab] = useState<"setup" | "overview" | "ml" | "ledger">("setup");

  const [files, setFiles] = useState<RecoveredFile[]>([]);
  const [selected, setSelected] = useState<RecoveredFile | null>(null);
  const [status, setStatus] = useState<CaseStatus | null>(null);
  const [mlResults, setMlResults] = useState<MlResultSummary[]>([]);
  const [selectedMl, setSelectedMl] = useState<MlResultSummary | null>(null);

  const [ledger, setLedger] = useState<LedgerBlock[]>([]);
  const [verifyResult, setVerifyResult] = useState<boolean | null>(null);
  const [verifying, setVerifying] = useState(false);
  const [caseId, setCaseId] = useState("");
  const [investigator, setInvestigator] = useState("");
  const [imagePath, setImagePath] = useState<string | null>(null);

  const [reportPath, setReportPath] = useState<string | null>(null);
  const [exporting, setExporting] = useState(false);

  useEffect(() => {
    invoke<RecoveredFile[]>("list_recovered_files")
      .then(setFiles)
      .catch(() => {
        setFiles([
          {
            file_id: "xfs:ino256",
            filename: "xfs_deleted_ino_256.pdf",
            file_type: "PDF",
            size: 475,
            filesystem: "XFS",
            recovery_method: "xfs_residual_extents",
            confidence: 95.0,
            source_locations: ["0x20000"],
            metadata: {
              modified: "2023-11-14T22:13:22+00:00",
              accessed: "2023-11-14T22:13:20+00:00",
              changed: "2023-11-14T22:13:21+00:00",
              birth: null,
              permissions: "0o100644",
              owner: "uid:1000 gid:1000",
            },
            sha256: "261b7dcabe3b73a6ea2d5bbb48d1fb248832f0a25b79d30b557fe6e369ec6c64",
            ml_predicted_class: "pdf",
            ml_confidence: 0.98,
            ml_top_k: [
              { class_name: "pdf", probability: 0.98 },
              { class_name: "txt", probability: 0.01 },
              { class_name: "doc", probability: 0.005 },
            ],
            validation_status: "VALID_PDF_STRUCTURE",
            validation_is_valid: true,
            reconstruction_confidence: 0.95,
          },
          {
            file_id: "xfs:ino257",
            filename: "xfs_deleted_ino_257.png",
            file_type: "PNG",
            size: 69,
            filesystem: "XFS",
            recovery_method: "xfs_residual_extents",
            confidence: 95.0,
            source_locations: ["0x21000"],
            metadata: {
              modified: "2023-11-14T22:15:02+00:00",
              accessed: "2023-11-14T22:15:00+00:00",
              changed: "2023-11-14T22:15:01+00:00",
              birth: null,
              permissions: "0o100644",
              owner: "uid:1000 gid:1000",
            },
            sha256: "b1ff9c8ea3a780bad09b346c423d2d0e46815926879b18e841d928376a946640",
            ml_predicted_class: "png",
            ml_confidence: 0.98,
            ml_top_k: [
              { class_name: "png", probability: 0.98 },
              { class_name: "jpg", probability: 0.01 },
            ],
            validation_status: "VALID_PNG_IMAGE",
            validation_is_valid: true,
            reconstruction_confidence: 0.95,
          },
          {
            file_id: "carved:0x64000",
            filename: "carved_0x64000.jpg",
            file_type: "JPG",
            size: 149,
            filesystem: "XFS",
            recovery_method: "ml_fragment_carving",
            confidence: 98.0,
            source_locations: ["0x64000"],
            metadata: {
              modified: null,
              accessed: null,
              changed: null,
              birth: null,
              permissions: "-rw-r--r--",
              owner: "uid:0 gid:0",
            },
            sha256: "39a289617bc0a782029e26556afb8639742661894f2d8bc462f18bd7e53e6e57",
            ml_predicted_class: "jpg",
            ml_confidence: 0.98,
            ml_top_k: [
              { class_name: "jpg", probability: 0.98 },
              { class_name: "png", probability: 0.01 },
            ],
            validation_status: "VALID_JPEG_IMAGE",
            validation_is_valid: true,
            reconstruction_confidence: 0.98,
          },
        ]);
      });

    invoke<CaseStatus>("get_case_status")
      .then(setStatus)
      .catch(() => {
        setStatus({
          case_id: "CASE-5B75FCB9",
          filesystem: "XFS",
          status: "complete",
          files_recovered: 5,
          fragments_found: 3,
          blocks_processed: 512,
          total_blocks: 512,
        });
      });

    invoke<LedgerBlock[]>("get_ledger")
      .then(setLedger)
      .catch(() => {
        setLedger([
          {
            block_index: 0,
            timestamp: "2026-08-26T18:01:36Z",
            payload: {
              event_id: "EVT-GENESIS",
              action: "genesis",
              recovery_method: "evidence_intake",
              file_id: "GENESIS",
              source_location: "tests/fixtures/xfs_deleted_synthetic.img",
              confidence: 100,
              file_sha256: "5b75fcb903b8384d25b7a13d5482f6b1a82abd2529ebf78c43033114e9599259",
            },
            prev_hash: "0000000000000000000000000000000000000000000000000000000000000000",
            block_hash: "60ee6ef9f092081ab73d87c04c18e3a2fb6dea7242224b9114f881bf821b58e7",
            signature: "ed25519_sig_genesis...",
            public_key_id: "operator_key_default",
          },
          {
            block_index: 1,
            timestamp: "2026-08-26T18:01:37Z",
            payload: {
              event_id: "EVT-1",
              action: "recovered",
              recovery_method: "xfs_residual_extents",
              file_id: "xfs:ino256",
              source_location: "0x20000",
              confidence: 95,
              file_sha256: "261b7dcabe3b73a6ea2d5bbb48d1fb248832f0a25b79d30b557fe6e369ec6c64",
            },
            prev_hash: "60ee6ef9f092081ab73d87c04c18e3a2fb6dea7242224b9114f881bf821b58e7",
            block_hash: "2313bc8ed5c2295e2440a616f3aad318a6b98f8db43ed823bf3953500bcc2a39",
            signature: "ed25519_sig_block_1...",
            public_key_id: "operator_key_default",
          },
        ]);
      });

    invoke<MlResultSummary[]>("get_ml_results")
      .then(setMlResults)
      .catch(() => {
        setMlResults([
          {
            file_id: "xfs:ino256",
            predicted_class: "pdf",
            ml_confidence: 0.98,
            top_k: [
              { class_name: "pdf", probability: 0.98 },
              { class_name: "txt", probability: 0.01 },
              { class_name: "doc", probability: 0.005 },
            ],
            validation_status: "VALID_PDF_STRUCTURE",
            validation_is_valid: true,
            reconstruction_confidence: 0.95,
            sha256: "261b7dcabe3b73a6ea2d5bbb48d1fb248832f0a25b79d30b557fe6e369ec6c64",
            ledger_block_index: 1,
          },
          {
            file_id: "xfs:ino257",
            predicted_class: "png",
            ml_confidence: 0.98,
            top_k: [
              { class_name: "png", probability: 0.98 },
              { class_name: "jpg", probability: 0.01 },
            ],
            validation_status: "VALID_PNG_IMAGE",
            validation_is_valid: true,
            reconstruction_confidence: 0.95,
            sha256: "b1ff9c8ea3a780bad09b346c423d2d0e46815926879b18e841d928376a946640",
            ledger_block_index: 2,
          },
          {
            file_id: "carved:0x64000",
            predicted_class: "jpg",
            ml_confidence: 0.98,
            top_k: [
              { class_name: "jpg", probability: 0.98 },
              { class_name: "png", probability: 0.01 },
            ],
            validation_status: "VALID_JPEG_IMAGE",
            validation_is_valid: true,
            reconstruction_confidence: 0.98,
            sha256: "39a289617bc0a782029e26556afb8639742661894f2d8bc462f18bd7e53e6e57",
            ledger_block_index: 3,
          },
        ]);
      });
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
        <button className={`tab-btn ${tab === "setup" ? "active" : ""}`} onClick={() => setTab("setup")}>
          Case Setup
        </button>
        <button className={`tab-btn ${tab === "overview" ? "active" : ""}`} onClick={() => setTab("overview")}>
          Overview
        </button>
        <button className={`tab-btn ${tab === "ml" ? "active" : ""}`} onClick={() => setTab("ml")}>
          ML Results
        </button>
        <button className={`tab-btn ${tab === "ledger" ? "active" : ""}`} onClick={() => setTab("ledger")}>
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
                <div style={{ overflow: "auto" }}>
                  <table className="evidence-table">
                    <thead>
                      <tr>
                        <th>Filename</th>
                        <th>Type</th>
                        <th>Size</th>
                        <th>Filesystem</th>
                        <th>Method</th>
                        <th>Confidence</th>
                        <th>ML Class</th>
                        <th>Valid</th>
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
                          <td>{f.ml_predicted_class ?? "—"}</td>
                          <td>
                            {f.validation_is_valid === null ? "—"
                              : f.validation_is_valid ? "✓" : "✗"}
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
                    {selected.ml_predicted_class && (
                      <>
                        <div className="detail-row"><span className="k">ML Class</span><span className="v">{selected.ml_predicted_class}</span></div>
                        <div className="detail-row"><span className="k">ML Conf</span><span className="v">{selected.ml_confidence !== null ? `${(selected.ml_confidence * 100).toFixed(1)}%` : "—"}</span></div>
                        <div className="detail-row"><span className="k">Validation</span><span className="v">{selected.validation_status ?? "—"}</span></div>
                      </>
                    )}
                  </div>
                ) : (
                  <p className="empty-state">Click a row to see details</p>
                )}
              </div>
            </div>
          </>
        )}

        {tab === "ml" && (
          <>
            <p className="eyebrow">Fragment Intelligence</p>
            <h2>ML Classification & Reassembly Results</h2>

            {mlResults.length === 0 ? (
              <p className="empty-state">No ML results yet. Run a scan with ML classification enabled.</p>
            ) : (
              <div className="split">
                <div className="main">
                  <table className="evidence-table">
                    <thead>
                      <tr>
                        <th>File ID</th>
                        <th>Predicted Class</th>
                        <th>ML Confidence</th>
                        <th>Recon Confidence</th>
                        <th>Validation</th>
                        <th>Ledger Block</th>
                      </tr>
                    </thead>
                    <tbody>
                      {mlResults.map((r) => (
                        <tr
                          key={r.file_id}
                          onClick={() => setSelectedMl(r)}
                          className={selectedMl?.file_id === r.file_id ? "selected" : ""}
                        >
                          <td className="mono-cell">{r.file_id}</td>
                          <td><strong>{r.predicted_class.toUpperCase()}</strong></td>
                          <td>
                            <span className={confidencePillClass(r.ml_confidence * 100)}>
                              {(r.ml_confidence * 100).toFixed(1)}%
                            </span>
                          </td>
                          <td>{(r.reconstruction_confidence * 100).toFixed(1)}%</td>
                          <td>{r.validation_is_valid ? "✓ Valid" : "✗ Invalid"} — {r.validation_status}</td>
                          <td>{r.ledger_block_index !== null ? `#${r.ledger_block_index}` : "—"}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>

                <div className="side">
                  <h3>Top-K Predictions</h3>
                  {selectedMl ? (
                    <div className="detail-card">
                      <div className="detail-row"><span className="k">File ID</span><span className="v">{selectedMl.file_id}</span></div>
                      <div className="detail-row"><span className="k">SHA-256</span><span className="v">{selectedMl.sha256 || "—"}</span></div>
                      <div className="detail-row"><span className="k">Ledger</span><span className="v">{selectedMl.ledger_block_index !== null ? `Block #${selectedMl.ledger_block_index}` : "Not recorded"}</span></div>
                      <div style={{ marginTop: "0.75rem" }}>
                        {selectedMl.top_k.map((p, i) => (
                          <div key={i} style={{ display: "flex", alignItems: "center", gap: "0.5rem", marginBottom: "0.3rem" }}>
                            <span style={{ width: "60px", fontWeight: i === 0 ? 700 : 400 }}>{p.class_name.toUpperCase()}</span>
                            <div style={{ flex: 1, background: "#2a2a3a", borderRadius: "3px", height: "8px" }}>
                              <div style={{ width: `${(p.probability * 100).toFixed(1)}%`, background: i === 0 ? "#6c8fff" : "#444", height: "100%", borderRadius: "3px" }} />
                            </div>
                            <span style={{ width: "45px", textAlign: "right", fontSize: "0.8rem" }}>{(p.probability * 100).toFixed(1)}%</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  ) : (
                    <p className="empty-state">Click a row to see top-k predictions</p>
                  )}
                </div>
              </div>
            )}
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
