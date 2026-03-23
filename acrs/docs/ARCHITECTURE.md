# SNSX CRS Architecture Notes

## End-to-End Experiment Flow

1. `POST /experiments/run`
2. `StaticAnalysisEngine` scans Python AST and flags unsafe patterns
3. `BinaryAnalysisEngine` performs binary metadata scan (adapter point for Ghidra/radare2)
4. `SymbolicExecutionEngine` evaluates path constraints (optional Z3)
5. `FuzzingAgent` mutates seed inputs and executes target harness
6. `FeatureExtractor` + `HeuristicVulnerabilityPredictor` estimate dominant vulnerability class
7. `ExploitStrategyPlanner` recommends next exploration strategy
8. `SecurityKnowledgeGraph` stores relationships between finding classes and severities
9. `ExperimentReport` is returned as structured output

## Safe Testing Model

- Run only against explicitly authorized targets.
- Use isolated containers/VMs for dynamic execution.
- Keep harness command explicit and auditable.

## Future Extensions

- Real disassembly/CFG extraction adapters for Ghidra and radare2.
- Coverage-guided instrumentation integration (AFL++/libFuzzer harnesses).
- CVE-grounded dataset and graph neural network predictors.
- Stateful autonomous experiment scheduler and replay pipelines.
