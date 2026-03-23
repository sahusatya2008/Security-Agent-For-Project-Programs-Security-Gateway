from fastapi import FastAPI, HTTPException

from core.pipeline import ExperimentOrchestrator
from core.schemas import ExperimentRequest, ExperimentResult, RemediationRequest, RemediationResult

app = FastAPI(title="SNSX CRS API", version="0.1.0")
orchestrator = ExperimentOrchestrator()


@app.get("/")
def index() -> dict[str, object]:
    return {
        "service": "snsx-crs",
        "status": "ok",
        "endpoints": [
            "/health",
            "/experiments/run",
            "/experiments/{experiment_id}",
            "/experiments/{experiment_id}/remediate",
        ],
    }


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "snsx-crs"}


@app.post("/experiments/run", response_model=ExperimentResult)
def run_experiment(payload: dict) -> ExperimentResult:
    try:
        normalized = dict(payload)
        if normalized.get("software_path", None) is None:
            normalized["software_path"] = ""
        request = ExperimentRequest(**normalized)
        return orchestrator.run(request)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Experiment failed: {exc}") from exc


@app.get("/experiments/{experiment_id}", response_model=ExperimentResult)
def get_experiment(experiment_id: str) -> ExperimentResult:
    result = orchestrator.get(experiment_id)
    if not result:
        raise HTTPException(status_code=404, detail="Experiment not found")
    return result


@app.post("/experiments/{experiment_id}/remediate", response_model=RemediationResult)
def remediate_experiment(experiment_id: str, request: RemediationRequest) -> RemediationResult:
    try:
        return orchestrator.remediate(experiment_id, request)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Remediation failed: {exc}") from exc
