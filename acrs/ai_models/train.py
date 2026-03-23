from __future__ import annotations

import argparse
from pathlib import Path

try:
    import torch
    import torch.nn as nn
    import torch.optim as optim

    from ai_models.model import VulnerabilityPredictorNN
except Exception as exc:
    raise SystemExit(f"PyTorch is required for training: {exc}") from exc


def train(output_path: Path, epochs: int = 5) -> None:
    model = VulnerabilityPredictorNN()
    optimizer = optim.Adam(model.parameters(), lr=1e-3)
    loss_fn = nn.CrossEntropyLoss()

    # Synthetic bootstrap dataset; replace with curated CVE-derived features.
    x = torch.randn(256, 16)
    y = torch.randint(0, 4, (256,))

    for epoch in range(epochs):
        optimizer.zero_grad()
        logits = model(x)
        loss = loss_fn(logits, y)
        loss.backward()
        optimizer.step()
        print(f"epoch={epoch + 1} loss={loss.item():.4f}")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    torch.save(model.state_dict(), output_path)
    print(f"saved model weights to {output_path}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Train SNSX CRS vulnerability predictor")
    parser.add_argument("--output", type=Path, default=Path("artifacts/model.pt"))
    parser.add_argument("--epochs", type=int, default=5)
    args = parser.parse_args()
    train(args.output, args.epochs)


if __name__ == "__main__":
    main()
