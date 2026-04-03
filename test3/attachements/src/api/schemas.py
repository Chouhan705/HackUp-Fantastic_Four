from pydantic import BaseModel
from typing import Optional

class TriggerResponse(BaseModel):
    message: str
    status: str

class AttachmentResponse(BaseModel):
    id: int
    filename: str
    sha256: str
    status: str
    risk_score: int