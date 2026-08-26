"""
Update notebooks with clean GitHub clone workflow and push to GitHub.
"""

import os
import json
import subprocess

def update_notebooks_for_github():
    cell_2_code = (
        "# =============================================================================\n"
        "# CELL 2: Clone SIH-FirSeFile Repository & Install Dependencies\n"
        "# =============================================================================\n"
        "!if [ ! -d \"/content/SIH-FirSeFile\" ]; then git clone https://github.com/kusha-l921/SIH-FirSeFile.git /content/SIH-FirSeFile; else cd /content/SIH-FirSeFile && git pull; fi\n"
        "%cd /content/SIH-FirSeFile\n"
        "\n"
        "!pip install -q timm transformers scikit-learn pandas seaborn matplotlib pyyaml networkx pillow\n"
        "\n"
        "import os\n"
        "import sys\n"
        "\n"
        "project_root = \"/content/SIH-FirSeFile\" if os.path.exists(\"/content/SIH-FirSeFile\") else os.path.abspath(\".\")\n"
        "if project_root not in sys.path:\n"
        "    sys.path.insert(0, project_root)\n"
        "\n"
        "print(f\"Working Directory: {os.getcwd()}\")\n"
        "print(f\"Source Packages:   {sorted(os.listdir(os.path.join(project_root, 'src')))}\")\n"
    )

    cell_6_code = (
        "# =============================================================================\n"
        "# CELL 6: Training-Pipeline Integration Audit\n"
        "# =============================================================================\n"
        "#\n"
        "# Verifies project structure and imports before GPU training.\n"
        "# =============================================================================\n"
        "\n"
        "from pathlib import Path\n"
        "import os\n"
        "import sys\n"
        "import importlib\n"
        "\n"
        "# Locate project root\n"
        "candidate_paths = [\n"
        "    Path(\"/content/SIH-FirSeFile\"),\n"
        "    Path(\"/content\"),\n"
        "    Path(\"/content/FirSeFile ML\"),\n"
        "    Path(os.path.abspath(\".\"))\n"
        "]\n"
        "\n"
        "project_root = None\n"
        "for p in candidate_paths:\n"
        "    if (p / \"src\" / \"training\" / \"train.py\").exists():\n"
        "        project_root = p\n"
        "        break\n"
        "\n"
        "if project_root is None:\n"
        "    raise FileNotFoundError(\"Could not find 'src/training/train.py'. Please run Cell 2 to clone the repository.\")\n"
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
        "for path in required_paths:\n"
        "    exists = path.exists()\n"
        "    print(f\"{'OK  ' if exists else 'MISS'} {path}\")\n"
        "    if not exists:\n"
        "        raise FileNotFoundError(f\"Missing required path: {path}\")\n"
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
                if 'CELL 2:' in source_text or 'CELL 2' in source_text or 'pip install' in source_text:
                    cell['source'] = [cell_2_code]
                elif 'CELL 6:' in source_text or 'CELL 6' in source_text or 'TRAINING PIPELINE INTEGRATION AUDIT' in source_text:
                    cell['source'] = [cell_6_code]

        with open(nb_path, 'w', encoding='utf-8') as f:
            json.dump(nb, f, indent=1)
        print(f"[OK] Updated {nb_path} with git clone workflow")

if __name__ == "__main__":
    update_notebooks_for_github()
