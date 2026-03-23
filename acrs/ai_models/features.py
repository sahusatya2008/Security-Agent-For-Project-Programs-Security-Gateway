from __future__ import annotations

import numpy as np


class FeatureExtractor:
    def extract(self, static_data: dict, fuzz_data: dict) -> np.ndarray:
        vector = np.zeros(16, dtype=np.float32)
        vector[0] = float(static_data.get("python_files_found", 0))
        vector[1] = float(static_data.get("finding_count", 0))
        vector[2] = float(fuzz_data.get("iterations", 0))
        vector[3] = float(fuzz_data.get("crash_count", 0))
        vector[4] = float(fuzz_data.get("unique_failures", 0))
        return vector
