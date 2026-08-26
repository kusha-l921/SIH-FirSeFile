#!/usr/bin/env python3
"""
FirSeFile Forensic API Server
=============================
High-performance REST API server bridging the Python forensic recovery pipeline,
Byte2Image neural feature extraction, Swin-V2 / Zero-Training ML classification,
graph-based fragment reassembly, format validation, and Ed25519 blockchain ledger
directly to the React/Tauri GUI.

Runs on http://127.0.0.1:8765
"""

import os
import sys
import json
import base64
import hashlib
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from pathlib import Path
from typing import Dict, Any, List

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from tools.run_recovery import run_forensic_pipeline, ForensicLedger
from src.models.zero_training_classifier import ZeroTrainingClassifier
from src.ml_pipeline import FragmentInput, classify_fragment, run_ml_pipeline, reassemble_fragments, validate_reconstruction
from src.validation.validator import validate_reconstructed_file
import blockchain_ledger

CURRENT_STATE: Dict[str, Any] = {
    "case_id": "CASE-5B75FCB9",
    "filesystem": "XFS",
    "status": "complete",
    "image_path": "tests/fixtures/xfs_deleted_synthetic.img",
    "files": [],
    "ledger": [],
    "ml_results": [],
    "blocks_processed": 512,
    "total_blocks": 512,
}


def load_initial_case():
    """Load default sample scan on startup so UI has instant real data."""
    default_img = PROJECT_ROOT / "tests" / "fixtures" / "xfs_deleted_synthetic.img"
    if default_img.exists():
        try:
            res = run_forensic_pipeline(str(default_img), output_dir="recovered_xfs_output", ledger_path="xfs_chain.jsonl")
            CURRENT_STATE["case_id"] = f"CASE-{res['image_sha256'][:8].upper()}"
            CURRENT_STATE["filesystem"] = res["detected_filesystem"].upper()
            CURRENT_STATE["status"] = "complete"
            CURRENT_STATE["image_path"] = str(default_img)
            CURRENT_STATE["files"] = res["recovered_files"]
            CURRENT_STATE["ledger"] = res["ledger_blocks"]
            CURRENT_STATE["blocks_processed"] = res["image_size_bytes"] // 4096
            CURRENT_STATE["total_blocks"] = res["image_size_bytes"] // 4096

            ml_summaries = []
            for f in res["recovered_files"]:
                ml_meta = f.get("ml_classification") or {}
                pred_class = ml_meta.get("predicted_class") or f.get("file_type", "unknown").lower()
                top_k = ml_meta.get("top_k") or [{"class": pred_class, "probability": f.get("confidence", 0.95)}]
                
                ml_summaries.append({
                    "file_id": f["file_id"],
                    "filename": f["filename"],
                    "predicted_class": pred_class,
                    "ml_confidence": f.get("confidence", 0.95),
                    "top_k": [{"class_name": item.get("class", item.get("class_name", "unknown")), "probability": item["probability"]} for item in top_k],
                    "validation_status": f.get("validation", {}).get("status", "VALID"),
                    "validation_is_valid": f.get("validation", {}).get("is_valid", True),
                    "reconstruction_confidence": f.get("confidence", 0.95),
                    "sha256": f.get("sha256", "N/A"),
                    "ledger_block_index": None,
                })
            CURRENT_STATE["ml_results"] = ml_summaries
        except Exception as e:
            print(f"[!] Initial scan load notice: {e}")


class ForensicAPIHandler(BaseHTTPRequestHandler):
    def _send_cors_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")

    def do_OPTIONS(self):
        self.send_response(200)
        self._send_cors_headers()
        self.end_headers()

    def _send_json(self, data: Any, status_code: int = 200):
        body = json.dumps(data).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self._send_cors_headers()
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        qs = parse_qs(parsed.query)

        if path == "/api/status":
            self._send_json({
                "case_id": CURRENT_STATE["case_id"],
                "filesystem": CURRENT_STATE["filesystem"],
                "status": CURRENT_STATE["status"],
                "image_path": CURRENT_STATE["image_path"],
                "files_recovered": len(CURRENT_STATE["files"]),
                "fragments_found": len([f for f in CURRENT_STATE["files"] if "carved" in f["file_id"]]),
                "blocks_processed": CURRENT_STATE["blocks_processed"],
                "total_blocks": CURRENT_STATE["total_blocks"],
            })
        elif path == "/api/files":
            self._send_json(CURRENT_STATE["files"])
        elif path == "/api/ledger":
            self._send_json(CURRENT_STATE["ledger"])
        elif path == "/api/ml_results":
            self._send_json(CURRENT_STATE["ml_results"])
        elif path == "/api/fixtures":
            fixtures_dir = PROJECT_ROOT / "tests" / "fixtures"
            fixtures = [f.name for f in fixtures_dir.glob("*.img")]
            self._send_json({"fixtures": fixtures})
        elif path == "/api/file_content":
            file_id = qs.get("file_id", [""])[0]
            matched = None
            for f in CURRENT_STATE["files"]:
                if f["file_id"] == file_id or f["filename"] == file_id:
                    matched = f
                    break

            if not matched:
                self._send_json({"error": "File not found"}, status_code=404)
                return

            out_dirs = [PROJECT_ROOT / "recovered_xfs_output", PROJECT_ROOT / "recovered_files", PROJECT_ROOT / "recovered_btrfs_output"]
            file_path = None
            for d in out_dirs:
                cand = d / matched["filename"]
                if cand.exists():
                    file_path = cand
                    break

            if file_path and file_path.exists():
                raw = file_path.read_bytes()
                hex_preview = " ".join(f"{b:02X}" for b in raw[:256])
                ascii_preview = "".join(chr(b) if 32 <= b <= 126 else "." for b in raw[:256])
                self._send_json({
                    "file_id": matched["file_id"],
                    "filename": matched["filename"],
                    "size_bytes": len(raw),
                    "sha256": hashlib.sha256(raw).hexdigest(),
                    "hex_preview": hex_preview,
                    "ascii_preview": ascii_preview,
                    "base64": base64.b64encode(raw[:8192]).decode("utf-8"),
                })
            else:
                self._send_json({"error": "File artifact not found on disk"}, status_code=404)
        else:
            self._send_json({"error": "Endpoint not found"}, status_code=404)

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path

        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode("utf-8") if content_length > 0 else "{}"
        try:
            req_data = json.loads(body)
        except Exception:
            req_data = {}

        if path == "/api/scan":
            image_path = req_data.get("image_path") or "tests/fixtures/xfs_deleted_synthetic.img"
            target_path = Path(image_path)
            if not target_path.is_absolute():
                target_path = PROJECT_ROOT / image_path

            if not target_path.exists():
                self._send_json({"error": f"Image not found: {target_path}"}, status_code=400)
                return

            try:
                out_dir = "recovered_files"
                ledger_path = "chain.jsonl"
                res = run_forensic_pipeline(str(target_path), output_dir=out_dir, ledger_path=ledger_path)

                CURRENT_STATE["case_id"] = req_data.get("case_id") or f"CASE-{res['image_sha256'][:8].upper()}"
                CURRENT_STATE["filesystem"] = res["detected_filesystem"].upper()
                CURRENT_STATE["status"] = "complete"
                CURRENT_STATE["image_path"] = str(target_path)
                CURRENT_STATE["files"] = res["recovered_files"]
                CURRENT_STATE["ledger"] = res["ledger_blocks"]
                CURRENT_STATE["blocks_processed"] = max(1, res["image_size_bytes"] // 4096)
                CURRENT_STATE["total_blocks"] = max(1, res["image_size_bytes"] // 4096)

                ml_summaries = []
                for f in res["recovered_files"]:
                    ml_meta = f.get("ml_classification") or {}
                    pred_class = ml_meta.get("predicted_class") or f.get("file_type", "unknown").lower()
                    top_k = ml_meta.get("top_k") or [{"class": pred_class, "probability": f.get("confidence", 0.95)}]
                    
                    ml_summaries.append({
                        "file_id": f["file_id"],
                        "filename": f["filename"],
                        "predicted_class": pred_class,
                        "ml_confidence": f.get("confidence", 0.95),
                        "top_k": [{"class_name": item.get("class", item.get("class_name", "unknown")), "probability": item["probability"]} for item in top_k],
                        "validation_status": f.get("validation", {}).get("status", "VALID"),
                        "validation_is_valid": f.get("validation", {}).get("is_valid", True),
                        "reconstruction_confidence": f.get("confidence", 0.95),
                        "sha256": f.get("sha256", "N/A"),
                        "ledger_block_index": None,
                    })
                CURRENT_STATE["ml_results"] = ml_summaries

                self._send_json({
                    "status": "success",
                    "case_id": CURRENT_STATE["case_id"],
                    "filesystem": CURRENT_STATE["filesystem"],
                    "total_files_recovered": len(CURRENT_STATE["files"]),
                    "files": CURRENT_STATE["files"],
                    "ledger": CURRENT_STATE["ledger"],
                    "ml_results": CURRENT_STATE["ml_results"],
                })
            except Exception as e:
                self._send_json({"error": str(e)}, status_code=500)

        elif path == "/api/verify":
            ledger = CURRENT_STATE["ledger"]
            if not ledger:
                self._send_json({"valid": False, "reason": "No blocks in ledger"})
                return

            pub_key = ledger[0].get("public_key_id") or ledger[0].get("payload", {}).get("operator_public_key", "")
            res = blockchain_ledger.verify_chain(ledger, pub_key)
            self._send_json(res)

        elif path == "/api/predict":
            fragment_path = req_data.get("fragment_path")
            raw_hex = req_data.get("raw_hex")

            if fragment_path:
                frag_p = Path(fragment_path)
                if not frag_p.is_absolute():
                    frag_p = PROJECT_ROOT / fragment_path
                if not frag_p.exists():
                    self._send_json({"error": "Fragment file not found"}, status_code=400)
                    return
                raw_bytes = frag_p.read_bytes()[:512]
            elif raw_hex:
                raw_bytes = bytes.fromhex(raw_hex.replace(" ", "").replace("\n", ""))[:512]
            else:
                self._send_json({"error": "Missing fragment_path or raw_hex"}, status_code=400)
                return

            zt = ZeroTrainingClassifier()
            pred = zt.predict_fragment(raw_bytes)
            val = validate_reconstructed_file(raw_bytes, expected_format=pred.predicted_class)

            self._send_json({
                "predicted_class": pred.predicted_class,
                "confidence": pred.confidence,
                "entropy": pred.entropy,
                "top_k": [{"class_name": cls, "probability": p} for cls, p in pred.top5],
                "validation": val.to_dict(),
            })

        elif path == "/api/export":
            case_id = req_data.get("case_id", CURRENT_STATE["case_id"])
            investigator = req_data.get("investigator", "Forensic Analyst")
            
            report = f"FIRSEFILE FORENSIC RECOVERY REPORT\n=================================\n"
            report += f"Case ID:      {case_id}\n"
            report += f"Investigator: {investigator}\n"
            report += f"Filesystem:   {CURRENT_STATE['filesystem']}\n"
            report += f"Files Recovered: {len(CURRENT_STATE['files'])}\n\n"
            report += "-- Recovered Files --\n"
            for f in CURRENT_STATE["files"]:
                report += f"[{f['file_id']}] {f.get('filename')} | {f.get('file_type')} | {f.get('file_size')} bytes | SHA256: {f.get('sha256')}\n"
            report += "\n-- Recovery Ledger --\n"
            for b in CURRENT_STATE["ledger"]:
                report += f"#{b.get('block_index')} | {b.get('timestamp')} | Hash: {b.get('block_hash')}\n"

            report_file = PROJECT_ROOT / f"recovered_{case_id}_report.txt"
            report_file.write_text(report, encoding="utf-8")
            self._send_json({"status": "success", "report_path": str(report_file)})
        else:
            self._send_json({"error": "Endpoint not found"}, status_code=404)


class ThreadedHTTPServer(HTTPServer):
    allow_reuse_address = True


def start_server(port: int = 8765):
    load_initial_case()
    server = ThreadedHTTPServer(("127.0.0.1", port), ForensicAPIHandler)
    print(f"[*] FirSeFile Forensic API Server active on http://127.0.0.1:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] API Server stopped.")
        server.server_close()


if __name__ == "__main__":
    start_server(8765)

