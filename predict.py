"""
Single-Fragment Forensic Classification CLI.
Evaluates an isolated binary file fragment using Byte2Image + Swin Transformer V2.

Usage:
    python predict.py --fragment path/to/fragment.bin [--checkpoint path/to/model.pt]
"""

import os
import sys
import argparse
import json
import torch

from src.models.classifier import FragmentClassifier
from src.models.zero_training_classifier import ZeroTrainingClassifier
from src.representations.byte2image import bytes_to_byte2image


def main():
    parser = argparse.ArgumentParser(description="Forensic File Fragment Classifier CLI")
    parser.add_argument("--fragment", type=str, required=True, help="Path to raw binary file fragment")
    parser.add_argument("--engine", type=str, default="swin_v2", choices=["swin_v2", "zero_training"], help="Classification engine: 'swin_v2' or 'zero_training'")
    parser.add_argument("--checkpoint", type=str, default=None, help="Path to trained Swin V2 model checkpoint (.pt)")
    parser.add_argument("--top_k", type=int, default=5, help="Number of top classes to display (default: 5)")
    parser.add_argument("--img_size", type=int, default=256, help="Byte2Image target dimension (default: 256)")
    parser.add_argument("--json", action="store_true", help="Output results in JSON format")

    args = parser.parse_args()

    if not os.path.exists(args.fragment):
        print(f"Error: Fragment file not found at '{args.fragment}'", file=sys.stderr)
        sys.exit(1)

    with open(args.fragment, "rb") as f:
        raw_bytes = f.read(512)

    fragment_id = os.path.basename(args.fragment)
    frag_size = len(raw_bytes)

    if args.engine == "zero_training":
        classifier = ZeroTrainingClassifier()
        pred = classifier.predict_fragment(raw_bytes)
        result = {
            "predicted_class": pred.predicted_class,
            "confidence": pred.confidence,
            "entropy": pred.entropy,
            "top_k_classes": [item[0] for item in pred.top5[:args.top_k]],
            "top_k_probabilities": [item[1] for item in pred.top5[:args.top_k]],
            "engine": "Zero-Training Hierarchical Forensic Engine (Structure + BFH + Texture)"
        }
        device = "CPU (Deterministic Statistical / Structural Engine)"
    else:
        device = "cuda" if torch.cuda.is_available() else "cpu"
        classifier = FragmentClassifier(
            checkpoint_path=args.checkpoint,
            device=device,
            img_size=args.img_size
        )
        res = classifier.predict_fragment(raw_bytes, top_k=args.top_k)
        result = {
            **res,
            "engine": "Byte2Image + Swin Transformer V2 (Tiny)"
        }

    if args.json:
        out_dict = {
            "fragment_id": fragment_id,
            "fragment_size_bytes": frag_size,
            "engine": result["engine"],
            "model_checkpoint": args.checkpoint or "N/A" if args.engine == "zero_training" else (args.checkpoint or "Untrained / Random Init (Demo Mode)"),
            "device": str(device),
            "predicted_class": result["predicted_class"],
            "confidence": round(result["confidence"], 4),
            "entropy": round(result["entropy"], 4),
            "top_k": [
                {"class": cls_name, "probability": round(prob, 4)}
                for cls_name, prob in zip(result["top_k_classes"], result["top_k_probabilities"])
            ]
        }
        print(json.dumps(out_dict, indent=2))
    else:
        print("\n=======================================================")
        print("  FORENSIC FILE-FRAGMENT CLASSIFICATION RESULT")
        print("=======================================================")
        print(f"Fragment ID:         {fragment_id}")
        print(f"Fragment Size:       {frag_size} bytes")
        print(f"Engine:              {result['engine']}")
        print(f"Inference Device:    {device}")
        print(f"Predicted Class:     {result['predicted_class'].upper()} (Confidence: {result['confidence']:.2%})")
        print(f"Predictive Entropy:  {result['entropy']:.4f}")
        print("-------------------------------------------------------")
        print("Top Predictions:")
        for cls_name, prob in zip(result["top_k_classes"], result["top_k_probabilities"]):
            bar = "#" * int(prob * 30)
            print(f"  {cls_name.upper():<8} {prob:6.2%}  {bar}")
        print("=======================================================")
        print("Note: Output reflects model probability distribution, not legal forensic proof.\n")


if __name__ == "__main__":
    main()
