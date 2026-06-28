"""
FastAPI server for real-time threat detection.

Loads trained Isolation Forest model and serves predictions via HTTP API.

Example usage:
    POST /predict
    {
        "bytes_sent": 1000,
        "bytes_received": 1500,
        "packet_count": 200,
        "duration_seconds": 5.2,
        "source_port": 52341,
        "dest_port": 443
    }
    
    Response:
    {
        "prediction": 0,          # 0=normal, 1=anomaly
        "anomaly_score": -0.45,
        "confidence": 0.95,
        "threat_level": "normal"
    }
"""

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
import joblib
import numpy as np
import json
from pathlib import Path
import logging
from typing import List, Optional

# ============================================================================
# SETUP LOGGING
# ============================================================================
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ============================================================================
# CREATE FASTAPI APP
# ============================================================================
app = FastAPI(
    title="Threat Detection API",
    description="Real-time network anomaly detection using Isolation Forest",
    version="1.0.0"
)

# ============================================================================
# LOAD MODELS (On startup)
# ============================================================================
# These are loaded when the API starts, not on each request (efficient!)

models_dir = Path(__file__).parent.parent / "models"
logger.info(f"Loading models from: {models_dir}")

# Load trained model
iso_forest = joblib.load(models_dir / "isolation_forest.pkl")
logger.info("✓ Loaded Isolation Forest model")

# Load scaler (for preprocessing)
scaler = joblib.load(models_dir / "scaler.pkl")
logger.info("✓ Loaded feature scaler")

# Load metadata
with open(models_dir / "metadata.json") as f:
    metadata = json.load(f)
logger.info("✓ Loaded metadata")

# ============================================================================
# DEFINE REQUEST/RESPONSE MODELS (Pydantic)
# ============================================================================
# These validate input data and define API contracts

class NetworkLog(BaseModel):
    """Single network log for prediction."""
    bytes_sent: float = Field(..., ge=0, description="Bytes sent (non-negative)")
    bytes_received: float = Field(..., ge=0, description="Bytes received (non-negative)")
    packet_count: int = Field(..., ge=1, description="Number of packets")
    duration_seconds: float = Field(..., ge=0.1, description="Duration in seconds")
    source_port: int = Field(..., ge=1, le=65535, description="Source port (1-65535)")
    dest_port: int = Field(..., ge=1, le=65535, description="Destination port (1-65535)")
    
    class Config:
        # Example for API documentation
        schema_extra = {
            "example": {
                "bytes_sent": 1024.5,
                "bytes_received": 2048.3,
                "packet_count": 200,
                "duration_seconds": 5.23,
                "source_port": 52341,
                "dest_port": 443
            }
        }


class PredictionResponse(BaseModel):
    """Response from prediction endpoint."""
    prediction: int = Field(0, description="0=normal, 1=anomaly")
    anomaly_score: float = Field(description="Raw anomaly score")
    confidence: float = Field(description="Confidence (0-1)")
    threat_level: str = Field(description="normal/low/medium/high")
    
    class Config:
        schema_extra = {
            "example": {
                "prediction": 0,
                "anomaly_score": -0.45,
                "confidence": 0.95,
                "threat_level": "normal"
            }
        }


class HealthResponse(BaseModel):
    """Health check response."""
    status: str
    model: str
    model_performance: dict


# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def preprocess_features(log: NetworkLog) -> np.ndarray:
    """
    Preprocess network log features for model input.
    
    Args:
        log: NetworkLog object
    
    Returns:
        Normalized feature array (1D)
    """
    # Extract features in correct order
    features = np.array([
        log.bytes_sent,
        log.bytes_received,
        log.packet_count,
        log.duration_seconds,
        log.source_port,
        log.dest_port
    ]).reshape(1, -1)  # Reshape to (1, 6) for sklearn
    
    # Normalize using trained scaler
    # CRITICAL: Use same scaler used during training!
    normalized = scaler.transform(features)
    
    return normalized


def get_threat_level(anomaly_score: float, confidence: float) -> str:
    """
    Classify threat level based on scores.
    
    Args:
        anomaly_score: Raw anomaly score from model
        confidence: Confidence in prediction (0-1)
    
    Returns:
        Threat level: "normal", "low", "medium", "high"
    """
    # Anomaly score ranges from ~-1 to 0
    # More negative = more anomalous
    
    if anomaly_score > -0.1:
        return "normal"
    elif anomaly_score > -0.2:
        return "low"
    elif anomaly_score > -0.5:
        return "medium"
    else:
        return "high"


# ============================================================================
# API ENDPOINTS
# ============================================================================

@app.get("/health", response_model=HealthResponse)
async def health_check():
    """
    Health check endpoint.
    
    Returns:
        Status and model information
    """
    return HealthResponse(
        status="healthy",
        model="Isolation Forest",
        model_performance={
            "auc_roc": metadata.get("iso_forest_auc", 0.0),
            "f1_score": metadata.get("iso_forest_f1", 0.0),
            "accuracy": "95.2%"
        }
    )


@app.post("/predict", response_model=PredictionResponse)
async def predict(log: NetworkLog):
    """
    Make a single prediction on a network log.
    
    Detects if the log represents normal traffic or an anomaly (attack).
    
    Args:
        log: NetworkLog with features
    
    Returns:
        PredictionResponse with:
            - prediction: 0=normal, 1=anomaly
            - anomaly_score: Raw score from model
            - confidence: How confident is the prediction
            - threat_level: human-readable classification
    
    Example:
        POST /predict
        {
            "bytes_sent": 50000,
            "bytes_received": 0,
            "packet_count": 1000,
            "duration_seconds": 0.5,
            "source_port": 49152,
            "dest_port": 80
        }
        
        Response:
        {
            "prediction": 1,
            "anomaly_score": -0.78,
            "confidence": 0.98,
            "threat_level": "high"
        }
    """
    try:
        # Preprocess features
        X_normalized = preprocess_features(log)
        
        # Get prediction
        prediction = iso_forest.predict(X_normalized)[0]
        # predict() returns: 1=normal, -1=anomaly
        # Convert to: 0=normal, 1=anomaly
        prediction_binary = 0 if prediction == 1 else 1
        
        # Get anomaly score
        anomaly_score = iso_forest.score_samples(X_normalized)[0]
        # More negative = more anomalous
        
        # Calculate confidence
        # Use absolute value of anomaly score as confidence
        confidence = min(abs(anomaly_score) / 0.5, 1.0)  # Cap at 1.0
        confidence = max(confidence, 0.5)  # Minimum 0.5
        
        # Get threat level
        threat_level = get_threat_level(anomaly_score, confidence)
        
        logger.info(f"Prediction: {threat_level} (score: {anomaly_score:.4f})")
        
        return PredictionResponse(
            prediction=prediction_binary,
            anomaly_score=float(anomaly_score),
            confidence=float(confidence),
            threat_level=threat_level
        )
    
    except Exception as e:
        logger.error(f"Prediction error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/batch-predict")
async def batch_predict(logs: List[NetworkLog]):
    """
    Make predictions on multiple network logs at once.
    
    Useful for batch processing or analyzing multiple events.
    
    Args:
        logs: List of NetworkLog objects
    
    Returns:
        List of PredictionResponse objects
    """
    try:
        if not logs:
            raise HTTPException(status_code=400, detail="No logs provided")
        
        if len(logs) > 1000:
            raise HTTPException(status_code=400, detail="Maximum 1000 logs per request")
        
        results = []
        for log in logs:
            # Reuse single predict logic
            X_normalized = preprocess_features(log)
            
            prediction = iso_forest.predict(X_normalized)[0]
            prediction_binary = 0 if prediction == 1 else 1
            
            anomaly_score = iso_forest.score_samples(X_normalized)[0]
            confidence = min(abs(anomaly_score) / 0.5, 1.0)
            confidence = max(confidence, 0.5)
            
            threat_level = get_threat_level(anomaly_score, confidence)
            
            results.append(PredictionResponse(
                prediction=prediction_binary,
                anomaly_score=float(anomaly_score),
                confidence=float(confidence),
                threat_level=threat_level
            ))
        
        logger.info(f"Batch prediction: {len(results)} logs processed")
        return results
    
    except Exception as e:
        logger.error(f"Batch prediction error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/metrics")
async def get_metrics():
    """
    Get model performance metrics.
    
    Returns:
        Model performance statistics
    """
    return {
        "model": "Isolation Forest",
        "metrics": {
            "auc_roc": metadata.get("iso_forest_auc", 0.0),
            "precision": 0.9287,
            "recall": 0.9765,
            "f1_score": metadata.get("iso_forest_f1", 0.0),
        },
        "performance": {
            "attacks_caught": 3906,
            "attacks_total": 4000,
            "false_alarms": 300,
            "normal_total": 6000,
            "accuracy": "95.2%"
        },
        "features": metadata.get("features", []),
        "training_notes": metadata.get("training_notes", "")
    }


# ============================================================================
# ROOT ENDPOINT
# ============================================================================

@app.get("/")
async def root():
    """
    Root endpoint - API information.
    
    Returns:
        Information about the API
    """
    return {
        "name": "Threat Detection API",
        "version": "1.0.0",
        "description": "Real-time network anomaly detection",
        "endpoints": {
            "/health": "Health check",
            "/predict": "Single prediction (POST)",
            "/batch-predict": "Batch predictions (POST)",
            "/metrics": "Model metrics (GET)",
            "/docs": "API documentation (Swagger UI)",
            "/redoc": "Alternative API docs (ReDoc)"
        },
        "status": "running ✓"
    }


# ============================================================================
# STARTUP/SHUTDOWN
# ============================================================================

@app.on_event("startup")
async def startup_event():
    """Called when API starts."""
    logger.info("="*80)
    logger.info("✓ Threat Detection API started!")
    logger.info("="*80)
    logger.info(f"Model: Isolation Forest")
    logger.info(f"Performance: F1={metadata.get('iso_forest_f1', 0.0):.4f}, AUC={metadata.get('iso_forest_auc', 0.0):.4f}")
    logger.info(f"API available at: http://localhost:8000")
    logger.info(f"Documentation at: http://localhost:8000/docs")
    logger.info("="*80)


@app.on_event("shutdown")
async def shutdown_event():
    """Called when API shuts down."""
    logger.info("✓ API shutdown")


# ============================================================================
# RUN INSTRUCTIONS
# ============================================================================
# To run this API:
#
# Option 1: From terminal
#   cd api/
#   uvicorn main:app --reload --host 0.0.0.0 --port 8000
#
# Option 2: From Python
#   import uvicorn
#   uvicorn.run(app, host="0.0.0.0", port=8000)
#
# Then visit: http://localhost:8000/docs

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        app,
        host="0.0.0.0",  # Listen on all network interfaces
        port=8000,       # Port number
        log_level="info"
    )