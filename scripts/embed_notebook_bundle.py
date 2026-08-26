"""
Script to embed codebase bundle into Colab training notebook for standalone execution.
"""

import os
import io
import zipfile
import base64
import json

def update_notebook():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
        for root_dir in ['src', 'configs', 'scripts']:
            for r, d, files in os.walk(root_dir):
                for f in files:
                    if f.endswith('.py') or f.endswith('.yaml') or f.endswith('.json'):
                        fp = os.path.join(r, f)
                        arcname = os.path.relpath(fp, '.')
                        zf.write(fp, arcname)

    data = buf.getvalue()
    b64_str = base64.b64encode(data).decode('ascii')

    cell_2_code = (
        "# =============================================================================\n"
        "# CELL 2: Install Dependencies & Setup Project Workspace (Auto-Extracts Source)\n"
        "# =============================================================================\n"
        "!pip install -q timm transformers scikit-learn pandas seaborn matplotlib pyyaml networkx pillow\n"
        "\n"
        "import os\n"
        "import sys\n"
        "import io\n"
        "import zipfile\n"
        "import base64\n"
        "\n"
        "project_root = \"/content\" if os.path.exists(\"/content\") else os.path.abspath(\".\")\n"
        "\n"
        "# Automatically unpack complete codebase into Colab environment if training module or configs are missing\n"
        "train_check = os.path.join(project_root, \"src\", \"training\", \"train.py\")\n"
        "cfg_check = os.path.join(project_root, \"configs\", \"smoke_test.yaml\")\n"
        "if not os.path.exists(train_check) or not os.path.exists(cfg_check):\n"
        "    print(\"Unpacking FirSeFile ML complete source and configs into Colab runtime...\")\n"
        f"    bundle_b64 = \"{b64_str}\"\n"
        "    zip_bytes = base64.b64decode(bundle_b64)\n"
        "    with zipfile.ZipFile(io.BytesIO(zip_bytes), \"r\") as zf:\n"
        "        zf.extractall(project_root)\n"
        "    print(f\"Successfully unpacked src/, configs/, and scripts/ into {project_root}!\")\n"
        "\n"
        "# Ensure project root is in sys.path\n"
        "if project_root not in sys.path:\n"
        "    sys.path.insert(0, project_root)\n"
        "\n"
        "print(f\"Workspace root: {project_root}\")\n"
        "print(f\"Modules available in src: {sorted(os.listdir(os.path.join(project_root, 'src')))}\")\n"
    )

    cell_6_code = (
        "# =============================================================================\n"
        "# CELL 6: Training-Pipeline Integration Audit\n"
        "# =============================================================================\n"
        "#\n"
        "# This cell does NOT train.\n"
        "# It verifies the existing project structure and imports before GPU work.\n"
        "# =============================================================================\n"
        "\n"
        "from pathlib import Path\n"
        "import os\n"
        "import sys\n"
        "import io\n"
        "import zipfile\n"
        "import base64\n"
        "import importlib\n"
        "\n"
        "project_root = Path(\"/content\") if Path(\"/content\").exists() else Path(os.path.abspath(\".\"))\n"
        "\n"
        "# Ensure complete codebase is present\n"
        "train_check = project_root / \"src\" / \"training\" / \"train.py\"\n"
        "cfg_check = project_root / \"configs\" / \"smoke_test.yaml\"\n"
        "if not train_check.exists() or not cfg_check.exists():\n"
        "    print(\"Syncing complete FirSeFile ML codebase into runtime...\")\n"
        f"    bundle_b64 = \"{b64_str}\"\n"
        "    zip_bytes = base64.b64decode(bundle_b64)\n"
        "    with zipfile.ZipFile(io.BytesIO(zip_bytes), \"r\") as zf:\n"
        "        zf.extractall(str(project_root))\n"
        "    print(\"Sync complete!\")\n"
        "\n"
        "if str(project_root) not in sys.path:\n"
        "    sys.path.insert(0, str(project_root))\n"
        "\n"
        "required_paths = [\n"
        "    project_root / \"src\" / \"training\" / \"train.py\",\n"
        "    project_root / \"configs\" / \"smoke_test.yaml\",\n"
        "    project_root / \"configs\" / \"pilot_run.yaml\",\n"
        "    project_root / \"configs\" / \"main_run.yaml\",\n"
        "]\n"
        "\n"
        "print(\"=\" * 70)\n"
        "print(\"TRAINING PIPELINE INTEGRATION AUDIT\")\n"
        "print(\"=\" * 70)\n"
        "\n"
        "missing = []\n"
        "for path in required_paths:\n"
        "    exists = path.exists()\n"
        "    print(f\"{'OK  ' if exists else 'MISS'} {path}\")\n"
        "    if not exists:\n"
        "        missing.append(str(path))\n"
        "\n"
        "if missing:\n"
        "    raise FileNotFoundError(f\"Missing required project files: {missing}\")\n"
        "\n"
        "matches = []\n"
        "for path in (project_root / \"src\").rglob(\"*.py\"):\n"
        "    try:\n"
        "        text = path.read_text(encoding=\"utf-8\", errors=\"ignore\")\n"
        "    except Exception:\n"
        "        continue\n"
        "    if \"bytes_to_byte2image\" in text or \"byte2image\" in text.lower() or \"Byte2Image\" in text:\n"
        "        matches.append(path)\n"
        "\n"
        "print(\"\\nByte2Image-related source files:\")\n"
        "for path in matches:\n"
        "    print(\"  \", path.relative_to(project_root))\n"
        "\n"
        "# Refresh sys.modules\n"
        "for mod_name in list(sys.modules.keys()):\n"
        "    if mod_name.startswith(\"src.\"):\n"
        "        del sys.modules[mod_name]\n"
        "\n"
        "module = importlib.import_module(\"src.representations.byte2image\")\n"
        "print(\"\\nLoaded representation module:\", module.__file__)\n"
        "assert hasattr(module, \"bytes_to_byte2image\"), \"Missing bytes_to_byte2image\"\n"
        "assert hasattr(module, \"byte2image_native\"), \"Missing byte2image_native\"\n"
        "print(\"[PASS] Correct Byte2Image module is importable.\")\n"
        "\n"
        "train_module = importlib.import_module(\"src.training.train\")\n"
        "print(\"Training module:\", train_module.__file__)\n"
        "if not hasattr(train_module, \"run_staged_training\"):\n"
        "    raise AttributeError(\"src.training.train does not expose run_staged_training.\")\n"
        "print(\"[PASS] run_staged_training is available.\")\n"
        "\n"
        "print(\"\\n\" + \"=\" * 70)\n"
        "print(\"INTEGRATION AUDIT COMPLETE\")\n"
        "print(\"=\" * 70)\n"
    )

    notebooks = [
        'notebooks/01_byte2image_swin_v2_training.ipynb',
        'notebooks/02_graph_reassembly_and_validation.ipynb',
        'notebooks/03_full_pipeline_demo.ipynb',
        'notebooks/04_zero_training_alternative_pipeline.ipynb'
    ]

    for nb_path in notebooks:
        if not os.path.exists(nb_path):
            continue
        with open(nb_path, 'r', encoding='utf-8') as f:
            nb = json.load(f)

        for cell in nb['cells']:
            if cell['cell_type'] == 'code':
                source_text = "".join(cell.get('source', []))
                if 'CELL 2:' in source_text or 'CELL 2' in source_text:
                    cell['source'] = [cell_2_code]
                elif 'CELL 6:' in source_text or 'CELL 6' in source_text or 'TRAINING PIPELINE INTEGRATION AUDIT' in source_text:
                    cell['source'] = [cell_6_code]

        with open(nb_path, 'w', encoding='utf-8') as f:
            json.dump(nb, f, indent=1)
        print(f"[OK] Updated {nb_path} with self-extracting codebase bundle!")

if __name__ == "__main__":
    update_notebook()
