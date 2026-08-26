"""
Swin Transformer V2 (Tiny) Model Adaptation for 1-Channel Byte2Image Representation.
Uses ImageNet-pretrained weights and adapts the input projection for 1-channel grayscale input.
"""

from typing import Dict, Any, Optional, List, Tuple
import torch
import torch.nn as nn
import torch.nn.functional as F

try:
    import timm
    HAS_TIMM = True
except ImportError:
    HAS_TIMM = False

try:
    import torchvision.models as tv_models
    HAS_TORCHVISION = True
except ImportError:
    HAS_TORCHVISION = False


class SwinV2TinyGrayscale(nn.Module):
    """
    ImageNet-Pretrained Swin Transformer V2 (Tiny) adapted for:
    1. Direct 1-Channel (Grayscale) Byte2Image input.
    2. 75-Class File-Fragment Classification Head.
    3. Staged Freezing / Unfreezing for controlled fine-tuning.
    """

    def __init__(
        self,
        num_classes: int = 75,
        pretrained: bool = True,
        img_size: int = 256,
        in_chans: int = 1,
        drop_rate: float = 0.1,
        drop_path_rate: float = 0.1
    ):
        super().__init__()
        self.num_classes = num_classes
        self.img_size = img_size
        self.in_chans = in_chans
        self.pretrained = pretrained

        # 1. Instantiate Backbone
        self.backbone, self.num_features = self._build_backbone(
            pretrained=pretrained,
            img_size=img_size,
            in_chans=in_chans,
            drop_rate=drop_rate,
            drop_path_rate=drop_path_rate
        )

        # 2. Forensic 75-Class Classification Head
        self.head = nn.Sequential(
            nn.LayerNorm(self.num_features),
            nn.Dropout(p=drop_rate),
            nn.Linear(self.num_features, num_classes)
        )

        self._init_head()

    def _build_backbone(
        self,
        pretrained: bool,
        img_size: int,
        in_chans: int,
        drop_rate: float,
        drop_path_rate: float
    ) -> Tuple[nn.Module, int]:
        """Build and adapt Swin Transformer V2 Tiny backbone."""
        if HAS_TIMM:
            model_name = f"swinv2_tiny_window16_{img_size}" if img_size in [256] else "swinv2_tiny_window8_256"
            try:
                # Attempt creating via timm with in_chans=in_chans (timm automatically handles 1-channel adaptation)
                backbone = timm.create_model(
                    model_name,
                    pretrained=pretrained,
                    in_chans=in_chans,
                    num_classes=0,  # Remove default classifier head
                    drop_rate=drop_rate,
                    drop_path_rate=drop_path_rate
                )
                num_features = backbone.num_features
                return backbone, num_features
            except Exception as e:
                # Fallback to standard swin_v2_tiny
                pass

        if HAS_TORCHVISION:
            # Fallback to torchvision swin_v2_t
            weights = tv_models.Swin_V2_T_Weights.DEFAULT if pretrained else None
            tv_swin = tv_models.swin_v2_t(weights=weights)

            # Adapt first patch partition layer for 1-channel input if needed
            if in_chans != 3:
                old_conv = tv_swin.features[0][0]  # Conv2d(3, 96, kernel_size=4, stride=4)
                new_conv = nn.Conv2d(
                    in_channels=in_chans,
                    out_channels=old_conv.out_channels,
                    kernel_size=old_conv.kernel_size,
                    stride=old_conv.stride,
                    padding=old_conv.padding,
                    bias=old_conv.bias is not None
                )
                if pretrained:
                    # Average the 3 RGB channel weights to preserve learned edge filters for grayscale
                    with torch.no_grad():
                        new_conv.weight.copy_(old_conv.weight.mean(dim=1, keepdim=True))
                        if old_conv.bias is not None:
                            new_conv.bias.copy_(old_conv.bias)
                tv_swin.features[0][0] = new_conv

            num_features = tv_swin.head.in_features
            tv_swin.head = nn.Identity()  # Remove head
            return tv_swin, num_features

        raise RuntimeError("Neither timm nor torchvision is available to instantiate Swin Transformer V2.")

    def _init_head(self):
        """Initialize classification head weights with Xavier normal."""
        for m in self.head.modules():
            if isinstance(m, nn.Linear):
                nn.init.trunc_normal_(m.weight, std=0.02)
                if m.bias is not None:
                    nn.init.constant_(m.bias, 0)
            elif isinstance(m, nn.LayerNorm):
                nn.init.constant_(m.bias, 0)
                nn.init.constant_(m.weight, 1.0)

    def forward_features(self, x: torch.Tensor) -> torch.Tensor:
        """Extract global feature vector."""
        if hasattr(self.backbone, "forward_features"):
            feat = self.backbone.forward_features(x)
            if hasattr(self.backbone, "forward_head"):
                # timm head processing without final linear
                feat = self.backbone.forward_head(feat, pre_logits=True)
            elif len(feat.shape) == 4:  # (B, H, W, C) or (B, C, H, W)
                if feat.shape[1] == self.num_features:
                    feat = feat.mean(dim=[-2, -1])
                else:
                    feat = feat.mean(dim=[1, 2])
            return feat
        elif hasattr(self.backbone, "features") and hasattr(self.backbone, "norm"):
            # Torchvision Swin implementation
            feat = self.backbone.features(x)
            feat = self.backbone.norm(feat)
            feat = self.backbone.permute(feat)
            feat = self.backbone.avgpool(feat)
            feat = self.backbone.flatten(feat)
            return feat
        else:
            feat = self.backbone(x)
            if len(feat.shape) > 2:
                feat = feat.view(feat.size(0), -1)
            return feat

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """
        Forward pass.
        Args:
            x: Tensor of shape (Batch_Size, 1, H, W)
        Returns:
            Logits of shape (Batch_Size, num_classes)
        """
        feat = self.forward_features(x)
        logits = self.head(feat)
        return logits

    def set_fine_tuning_stage(self, stage: str = "A"):
        """
        Configure staged fine-tuning.
        - Stage A (Initial): Train head and high-level transformer blocks only. Freeze lower layers.
        - Stage B (Full): Unfreeze all transformer stages for end-to-end refinement with small LR.
        """
        if stage.upper() == "A":
            # Freeze all backbone parameters first
            for param in self.backbone.parameters():
                param.requires_grad = False

            # Unfreeze highest Swin stages if accessible
            if hasattr(self.backbone, "layers"):
                # Unfreeze last layer / stage
                for param in self.backbone.layers[-1].parameters():
                    param.requires_grad = True
            elif hasattr(self.backbone, "features"):
                for param in self.backbone.features[-2:].parameters():
                    param.requires_grad = True

            # Classification head is always trainable
            for param in self.head.parameters():
                param.requires_grad = True

        elif stage.upper() == "B":
            # Unfreeze entire network
            for param in self.parameters():
                param.requires_grad = True
        else:
            raise ValueError(f"Unknown fine-tuning stage '{stage}'. Choose 'A' or 'B'.")
