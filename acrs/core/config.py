from dataclasses import dataclass


@dataclass(slots=True)
class RuntimeConfig:
    default_fuzz_iterations: int = 50
    max_fuzz_iterations: int = 10_000
    allow_network: bool = False
