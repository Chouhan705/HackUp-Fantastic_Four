from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from api.scan_route import router as scan_router

app = FastAPI(title="Phishing Detective API")

# Add CORS middleware to allow the Chrome extension to communicate with the backend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Adjust this to the specific Chrome extension ID if needed
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include the scan route from the fetcher extension
app.include_router(scan_router)

@app.get("/")
def read_root():
    return {"message": "Phishing Detective API is running!"}
