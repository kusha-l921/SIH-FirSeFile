"""
Phase 2 Main Training Runner.
Executes 2,000 samples/class (~150,000 samples) full fine-tuning run.
"""

import os
import sys
import yaml

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.training.train import run_staged_training
from src.utils.colab_utils import print_colab_environment_info, setup_google_drive


def main():
    print_colab_environment_info()
    backup_dir = setup_google_drive()

    config_path = "configs/main_run.yaml"
    with open(config_path, "r", encoding="utf-8") as f:
        config = yaml.safe_load(f)

    print("Launching Phase 2 Main Fine-Tuning Run (150,000 samples)...")
    result = run_staged_training(config, drive_backup_dir=backup_dir)
    print("\n[SUCCESS] Phase 2 Main Training Run Finished!")
    print(f"Best Validation Macro-F1: {result['best_val_macro_f1']:.4f} (Epoch {result['best_epoch']})")


if __name__ == "__main__":
    main()
