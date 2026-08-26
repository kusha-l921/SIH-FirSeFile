"""
Phase 1 Pilot Training Runner.
Executes 1,000 samples/class (~75,000 samples) fine-tuning run.
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

    config_path = "configs/pilot_run.yaml"
    with open(config_path, "r", encoding="utf-8") as f:
        config = yaml.safe_load(f)

    print("Launching Phase 1 Pilot Fine-Tuning Run...")
    result = run_staged_training(config, drive_backup_dir=backup_dir)
    print("\n[SUCCESS] Phase 1 Pilot Run Finished!")
    print(f"Best Validation Macro-F1: {result['best_val_macro_f1']:.4f} (Epoch {result['best_epoch']})")


if __name__ == "__main__":
    main()
