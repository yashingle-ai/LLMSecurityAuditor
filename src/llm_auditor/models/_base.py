from pydantic import BaseModel, ConfigDict


class StrictModel(BaseModel):
    """Base for every auditor model: unknown fields are errors, never silently dropped."""

    model_config = ConfigDict(extra="forbid")
