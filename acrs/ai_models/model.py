from __future__ import annotations

from typing import Any

import numpy as np

try:
    import torch
    import torch.nn as nn

    TORCH_AVAILABLE = True
except Exception:
    TORCH_AVAILABLE = False


if TORCH_AVAILABLE:
    class VulnerabilityPredictorNN(nn.Module):
        def __init__(self, input_dim: int = 16, output_dim: int = 4) -> None:
            super().__init__()
            self.layers = nn.Sequential(
                nn.Linear(input_dim, 64),
                nn.ReLU(),
                nn.Linear(64, 32),
                nn.ReLU(),
                nn.Linear(32, output_dim),
            )

        def forward(self, x: torch.Tensor) -> torch.Tensor:
            return self.layers(x)
else:
    class VulnerabilityPredictorNN:
        def __init__(self, *args, **kwargs) -> None:
            raise RuntimeError("PyTorch is not installed. Install with `pip install -e .[ml]`.")


class HeuristicVulnerabilityPredictor:
    labels = ["low-risk", "input-validation", "memory-safety", "code-exec"]

    def predict(self, features: np.ndarray) -> dict[str, Any]:
        score = float(features[1] * 0.2 + features[3] * 0.6 + features[4] * 0.2)
        idx = 0
        if score > 10:
            idx = 3
        elif score > 5:
            idx = 2
        elif score > 1:
            idx = 1
        return {
            "model": "heuristic" if not TORCH_AVAILABLE else "torch-ready-heuristic",
            "predicted_label": self.labels[idx],
            "risk_score": round(min(score / 20.0, 1.0), 3),
            "summary": f"Predicted dominant pattern: {self.labels[idx]}",
        }
