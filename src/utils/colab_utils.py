"""
Google Colab Runtime Diagnostics and Drive Utilities.
"""

import os
import sys
import torch


def print_colab_environment_info():
    """
    Inspect and display runtime GPU, CUDA, and environment hardware specs.
    """
    print("\n=======================================================")
    print("       GOOGLE COLAB / RUNTIME HARDWARE DIAGNOSTICS")
    print("=======================================================")
    print(f"Python Version:   {sys.version.split()[0]}")
    print(f"PyTorch Version:  {torch.__version__}")

    if torch.cuda.is_available():
        gpu_name = torch.cuda.get_device_name(0)
        vram_gb = torch.cuda.get_device_properties(0).total_memory / (1024**3)
        cuda_ver = torch.version.cuda
        print(f"CUDA Available:   YES (CUDA {cuda_ver})")
        print(f"GPU Model:        {gpu_name}")
        print(f"Total VRAM:       {vram_gb:.2f} GB")
        
        # Recommendation
        if vram_gb >= 30:
            rec_batch = 128
        elif vram_gb >= 14:
            rec_batch = 64
        else:
            rec_batch = 32
        print(f"Recommended Batch Size: {rec_batch}")
    else:
        print("CUDA Available:   NO (Running on CPU)")
        print("Recommended Batch Size: 16")

    print("=======================================================\n")


def setup_google_drive(mount_point: str = "/content/drive") -> str:
    """
    Mount Google Drive if running inside a Colab session.
    """
    try:
        from google.colab import drive
        drive.mount(mount_point)
        backup_dir = os.path.join(mount_point, "MyDrive", "FirSeFile_Checkpoints")
        os.makedirs(backup_dir, exist_ok=True)
        print(f"Google Drive mounted successfully. Backup path: {backup_dir}")
        return backup_dir
    except ImportError:
        print("Not running in an active Google Colab kernel. Local storage will be used.")
        return "./checkpoints"


def setup_backup_directory(use_google_drive: bool = False) -> str:
    """
    Setup local or Google Drive backup directory.
    """
    if use_google_drive:
        try:
            return setup_google_drive()
        except Exception as e:
            print(f"Google Drive mount failed: {e}")
    local_backup_path = os.path.join(os.getcwd(), "local_backups")
    os.makedirs(local_backup_path, exist_ok=True)
    print(f"Using local backup directory: {local_backup_path}")
    return local_backup_path

