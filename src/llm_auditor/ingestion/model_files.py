"""Model weight files. Loading only identifies them; SC-01 inspects pickle-based ones
without ever unpickling them."""

from pathlib import Path

from llm_auditor.ingestion.base import Artifact, IngestReport
from llm_auditor.models import ModelFile
from llm_auditor.models.artifacts import ModelFormat

FORMATS: dict[str, ModelFormat] = {
    ".pkl": "pickle",
    ".pickle": "pickle",
    ".joblib": "pickle",
    ".pt": "pytorch",
    ".pth": "pytorch",
    ".bin": "pytorch",
    ".ckpt": "pytorch",
    ".safetensors": "safetensors",
    ".onnx": "onnx",
    ".gguf": "gguf",
    ".h5": "keras",
    ".keras": "keras",
}


class ModelFileLoader:
    extensions = frozenset(FORMATS)

    def load(self, file: Path, rel: str, report: IngestReport) -> list[Artifact]:
        model_format = FORMATS.get(file.suffix.lower())
        if model_format is None:
            report.warn(rel, "skipped: not a recognized model file")
            return []
        try:
            size = file.stat().st_size
        except OSError as error:
            report.warn(rel, f"skipped: {error.strerror or error}")
            return []
        return [ModelFile(path=rel, format=model_format, size_bytes=size)]
