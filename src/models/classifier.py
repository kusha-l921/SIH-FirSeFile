"""
High-Level File Fragment Classifier Wrapper.
Handles inference, checkpoint management, Top-K probability extraction, and confidence scoring.
"""

from typing import Dict, Any, List, Optional, Tuple, Union
import os
import torch
import torch.nn.functional as F
import numpy as np

from src.datasets.fft75 import FFT75_CLASSES, IDX_TO_CLASS, get_class_name
from src.representations.byte2image import Byte2ImageTransform, bytes_to_byte2image
from src.models.swin_v2 import SwinV2TinyGrayscale
from dataclasses import dataclass


@dataclass
class FragmentPrediction:
    predicted_class: str
    class_idx: int
    confidence: float
    entropy: float
    all_probabilities: np.ndarray
    top5: List[Tuple[str, float]]
    is_confident: bool = True


class FragmentClassifier:
    """
    Forensic File-Fragment Classifier integrating Byte2Image and Swin Transformer V2.
    """

    def __init__(
        self,
        model: Optional[SwinV2TinyGrayscale] = None,
        checkpoint_path: Optional[str] = None,
        device: Optional[str] = None,
        img_size: int = 256,
        num_classes: int = 75
    ):
        if device is None:
            self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        else:
            self.device = torch.device(device)

        self.img_size = img_size
        self.num_classes = num_classes
        self.transform = Byte2ImageTransform(target_size=(img_size, img_size), normalize=True)

        if model is not None:
            self.model = model.to(self.device)
        else:
            self.model = SwinV2TinyGrayscale(
                num_classes=num_classes,
                pretrained=False,
                img_size=img_size,
                in_chans=1
            ).to(self.device)

        if checkpoint_path and os.path.exists(checkpoint_path):
            self.load_checkpoint(checkpoint_path)

        self.model.eval()

    def load_checkpoint(self, checkpoint_path: str):
        """Load weights from checkpoint."""
        state = torch.load(checkpoint_path, map_location=self.device, weights_only=False)
        if "model_state_dict" in state:
            self.model.load_state_dict(state["model_state_dict"])
        elif "state_dict" in state:
            self.model.load_state_dict(state["state_dict"])
        else:
            self.model.load_state_dict(state)
        self.model.eval()

    def predict_fragment(
        self,
        raw_bytes: bytes,
        top_k: int = 5
    ) -> Dict[str, Any]:
        """
        Predict file format probabilities for a single raw fragment.

        Returns:
            Dict with:
            - 'predicted_class': top-1 class name
            - 'confidence': top-1 softmax probability
            - 'entropy': predictive entropy (lower = higher certainty)
            - 'top_k_classes': list of top-k class names
            - 'top_k_probabilities': list of top-k probabilities
            - 'all_probabilities': dict of class_name -> probability
        """
        tensor_img = self.transform(raw_bytes).unsqueeze(0).to(self.device)  # (1, 1, H, W)
        
        with torch.no_grad():
            logits = self.model(tensor_img)
            probs = F.softmax(logits, dim=-1).squeeze(0).cpu().numpy()

        top_k_indices = np.argsort(probs)[::-1][:top_k]
        top_k_classes = [get_class_name(int(idx)) for idx in top_k_indices]
        top_k_probs = [float(probs[idx]) for idx in top_k_indices]

        # Calculate Shannon entropy: H(p) = - sum(p * log(p))
        eps = 1e-12
        entropy = float(-np.sum(probs * np.log(probs + eps)))

        all_prob_dict = {get_class_name(i): float(probs[i]) for i in range(len(probs))}

        return {
            "predicted_class": top_k_classes[0],
            "confidence": top_k_probs[0],
            "entropy": entropy,
            "top_k_classes": top_k_classes,
            "top_k_probabilities": top_k_probs,
            "all_probabilities": all_prob_dict
        }

    def predict_batch(
        self,
        batch_bytes: List[bytes],
        top_k: int = 5
    ) -> List[Dict[str, Any]]:
        """Predict for a batch of raw binary fragments."""
        if not batch_bytes:
            return []

        tensors = [self.transform(b) for b in batch_bytes]
        batch_tensor = torch.stack(tensors, dim=0).to(self.device)  # (B, 1, H, W)

        with torch.no_grad():
            logits = self.model(batch_tensor)
            probs = F.softmax(logits, dim=-1).cpu().numpy()

        results = []
        eps = 1e-12
        for i in range(len(batch_bytes)):
            p = probs[i]
            top_k_indices = np.argsort(p)[::-1][:top_k]
            top_k_classes = [get_class_name(int(idx)) for idx in top_k_indices]
            top_k_probs = [float(p[idx]) for idx in top_k_indices]
            entropy = float(-np.sum(p * np.log(p + eps)))

            results.append({
                "predicted_class": top_k_classes[0],
                "confidence": top_k_probs[0],
                "entropy": entropy,
                "top_k_classes": top_k_classes,
                "top_k_probabilities": top_k_probs,
                "all_probabilities": {get_class_name(j): float(p[j]) for j in range(len(p))}
            })

        return results
