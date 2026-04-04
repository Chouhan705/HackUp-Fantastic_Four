from fastapi import FastAPI
from pydantic import BaseModel
from model.predict import predict_phishing

app = FastAPI(title="Phishing Detection API 🚀")

class EmailRequest(BaseModel):
    text: str
    url: str
    work_hours: int = 1
    workdays: int = 1

from fastapi.responses import Response

@app.get("/favicon.ico")
def favicon():
    return Response(status_code=204)

@app.get("/")
def home():
    return {"message": "API running 🚀"}

@app.post("/predict")
def predict(data: EmailRequest):
    result = predict_phishing(
        data.text,
        data.url,
        data.work_hours,
        data.workdays
    )
    return result