# Digital-Forensics File-Fragment Intelligence Module

An end-to-end experimental prototype for digital forensics and file carving from deleted XFS and Btrfs filesystem blocks.

## Proposed Architecture

$$\text{Raw 512-Byte Fragment} \xrightarrow{\text{Byte2Image}} \text{2D Grayscale Representation} \xrightarrow{\text{Swin Transformer V2 Tiny}} \text{75-Class Probabilities} \xrightarrow{\text{Graph Reassembly}} \text{Ordered Sequence} \xrightarrow{\text{Structural Validator}} \text{Forensic Recovery}$$

```
RAW / UNRESOLVED FILE FRAGMENT (512-byte sectors)
               │
               ▼
   BYTE-TO-IMAGE TRANSFORMATION (1-bit sliding window + N-gram stacking)
               │
               ▼
     2D GRAYSCALE REPRESENTATION (256x256 / 224x224)
               │
               ▼
    SWIN TRANSFORMER V2 (TINY) (ImageNet Pretrained + 1-Channel Adaptation)
               │
               ▼
  FILE-TYPE / FRAGMENT CLASSIFIER (75 FFT-75 classes + confidence scores)
               │
               ▼
     GRAPH-BASED REASSEMBLY (Multi-component edge scoring + Beam search)
               │
               ▼
        RECONSTRUCTED FILE (Contiguous stitched byte stream)
               │
               ▼
     FORMAT-AWARE VALIDATION (Deep structural parsing: PDF, ZIP, PNG, ELF, SQLite)
```

---

## Key Features

1. **Byte2Image 2D Representation** (`src/representations/byte2image.py`):
   - Exposes intra-byte (bit-level 1-bit sliding window) and inter-byte transitions.
   - Deterministic 2D grayscale transformation without naive 1:1 pixel degradation.
2. **Swin Transformer V2 (Tiny)** (`src/models/swin_v2.py`):
   - 1-channel direct grayscale patch projection adaptation.
   - 75-class classification head with staged fine-tuning (Stage A $\rightarrow$ Stage B).
3. **FFT-75 Forensic Dataset Engine** (`src/datasets/fft75.py`, `src/datasets/fragment_dataset.py`):
   - 75 forensic classes across 11 category tags.
   - Leak-free partitioning at the source file level.
4. **Graph-Based Fragment Reassembly** (`src/reassembly/`):
   - Directed candidate adjacency graph with multi-component edge scoring:
     $$S(u, v) = w_1 S_{\text{type}} + w_2 S_{\text{conf}} + w_3 S_{\text{boundary}} + w_4 S_{\text{format}} + w_5 S_{\text{locality}}$$
   - Beam-search heuristic ordering finding maximum likelihood sequence.
5. **Format-Aware Structural Validator** (`src/validation/validator.py`):
   - Structural integrity parsing for PDF, ZIP/DOCX, JPEG, PNG, ELF, SQLite, and Scripts.
   - Generates SHA-256 hash and forensic provenance metadata.
6. **Google Colab Free GPU Integration**:
   - Ready-to-run Jupyter notebooks in `notebooks/` configured for Colab's Free GPU (T4 / V100).
   - Staged training pipeline: Phase 0 Smoke Test $\rightarrow$ Phase 1 Pilot Run $\rightarrow$ Phase 2 Main Run.

---

## Directory Structure

```
project/
├── data/                       # Fragment samples and binaries
├── configs/                    # Experiment configuration YAMLs
│   ├── smoke_test.yaml
│   ├── pilot_run.yaml
│   └── main_run.yaml
├── checkpoints/                # Saved model weights (.pt)
├── experiments/                # Metric summaries, CSV reports, and plots
├── notebooks/                  # Interactive Colab-ready Jupyter notebooks
│   ├── 01_byte2image_swin_v2_training.ipynb
│   ├── 02_graph_reassembly_and_validation.ipynb
│   └── 03_full_pipeline_demo.ipynb
├── src/
│   ├── datasets/               # FFT-75 ontology and PyTorch loaders
│   ├── representations/        # Byte2Image bit-shift & grayscale transforms
│   ├── models/                 # Swin V2 Tiny & Classifier wrapper
│   ├── baselines/              # Published ByteFormer baseline reference
│   ├── training/               # Staged fine-tuning, evaluation, metrics
│   ├── reassembly/             # Graph formulation, edge scoring, beam search
│   ├── validation/             # Deep format-aware parsers
│   └── utils/                  # Colab environment diagnostics & Google Drive tools
├── scripts/                    # Automation scripts for experiments
├── tests/                      # Pytest unit and integration test suite
├── predict.py                  # Single-fragment CLI prediction tool
├── requirements.txt
└── README.md
```

---

## Quick Start & Usage

### 1. Installation
```bash
pip install -r requirements.txt
```

### 2. Run Tests
```bash
pytest tests/ -v
```

### 3. Single-Fragment CLI Prediction
```bash
python predict.py --fragment data/sample_fragment.bin
```

### 4. Run Phase 0 Smoke Test
```bash
python scripts/run_smoke_test.py
```

### 5. Run Reassembly & Format Validation Benchmark
```bash
python scripts/run_reassembly_eval.py
```

### 6. Run Training on Google Colab Free GPU
Open `notebooks/01_byte2image_swin_v2_training.ipynb` in the IDE using the **Google Colab extension** and connect to the free GPU runtime.

---

## FFT-75 Literature Baseline Comparison

| Method | Fragment Size | Classes | Top-1 Accuracy | Top-5 Accuracy | Macro F1 | Inference Speed | Result Source | Evaluation Protocol |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :--- | :--- |
| **ByteFormer (1D Transformer)** | 512 B | 75 | 72.50% | 88.40% | 0.7180 | N/A (Published) | Published Literature (IEEE/arXiv) | FFT-75 Scenario #1 (512B) |
| **FiFTy (CNN Baseline)** | 512 B | 75 | 65.20% | 81.10% | 0.6390 | N/A (Published) | Published Literature | FFT-75 Scenario #1 (512B) |
| **Our Byte2Image + Swin V2 (Tiny)** | 512 B | 75 | Measured | Measured | Measured | Measured | Our Measured Experimental Prototype | Leak-Free Source Partition |
