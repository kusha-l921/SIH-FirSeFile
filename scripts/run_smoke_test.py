"""
Phase 0 Smoke Test Runner.
Executes rapid end-to-end verification of dataset loading, Byte2Image conversion,
Swin V2 forward/backward passes, and checkpoint saving.
"""

import os
import sys
import yaml

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.training.train import run_staged_training
from src.utils.colab_utils import print_colab_environment_info


def main():
    print_colab_environment_info()

    config_path = "configs/smoke_test.yaml"
    with open(config_path, "r", encoding="utf-8") as f:
        config = yaml.safe_load(f)

    print("Running Phase 0 Smoke Test...")
    result = run_staged_training(config)
    print("\n[SUCCESS] Phase 0 Smoke Test Completed Successfully!")
    print(f"Checkpoints directory: {result['checkpoints_dir']}")


if __name__ == "__main__":
    main()
