import os
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from typing import Dict, Any, Optional

from backend.data_handler import preprocess_single_flow, DATA_FILE, FEATURE_COLUMNS
from backend.model_handler import train_ids_model, load_trained_model, predict_single_flow
from backend.xai_handler import explain_prediction
from backend.sniff_handler import global_sniffer
from backend.recommendation_engine import get_recommendations

app = FastAPI(title="Explainable AI Intrusion Detection System", version="1.0.0")

# Enable CORS for local development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Flow Input Model for Manual Analysis
class FlowInput(BaseModel):
    destination_port: float = Field(..., alias="Destination Port")
    flow_duration: float = Field(..., alias="Flow Duration")
    total_fwd_packets: float = Field(..., alias="Total Fwd Packets")
    total_backward_packets: float = Field(..., alias="Total Backward Packets")
    total_length_of_fwd_packets: float = Field(..., alias="Total Length of Fwd Packets")
    total_length_of_bwd_packets: float = Field(..., alias="Total Length of Bwd Packets")
    fwd_packet_length_max: float = Field(..., alias="Fwd Packet Length Max")
    fwd_packet_length_min: float = Field(..., alias="Fwd Packet Length Min")
    fwd_packet_length_mean: float = Field(..., alias="Fwd Packet Length Mean")
    bwd_packet_length_max: float = Field(..., alias="Bwd Packet Length Max")
    bwd_packet_length_min: float = Field(..., alias="Bwd Packet Length Min")
    bwd_packet_length_mean: float = Field(..., alias="Bwd Packet Length Mean")
    flow_bytes_s: float = Field(..., alias="Flow Bytes/s")
    flow_packets_s: float = Field(..., alias="Flow Packets/s")
    flow_iat_mean: float = Field(..., alias="Flow IAT Mean")
    flow_iat_max: float = Field(..., alias="Flow IAT Max")
    fwd_header_length: float = Field(..., alias="Fwd Header Length")
    bwd_header_length: float = Field(..., alias="Bwd Header Length")
    packet_length_mean: float = Field(..., alias="Packet Length Mean")
    average_packet_size: float = Field(..., alias="Average Packet Size")

    class Config:
        populate_by_name = True

class ToggleAttacksInput(BaseModel):
    enabled: bool


@app.get("/api/status")
def get_status():
    """
    Checks if the model is trained and returns server configurations.
    """
    model_exists = os.path.exists(os.path.join(os.path.dirname(__file__), '..', 'data', 'model.joblib'))
    return {
        "status": "online",
        "model_trained": model_exists,
        "sniffer_running": global_sniffer.is_running,
        "sniffer_fallback_mode": global_sniffer.fallback_mode,
        "dataset_exists": os.path.exists(DATA_FILE),
        "simulate_attacks": getattr(global_sniffer, 'simulate_attacks', True)
    }

@app.post("/api/train")
def trigger_training():
    """
    Triggers the training of the Random Forest model and returns the metrics.
    """
    try:
        _, metrics = train_ids_model(num_samples=10000)
        return {
            "success": True,
            "message": "Model trained successfully.",
            "metrics": metrics
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Training failed: {str(e)}")

@app.get("/api/metrics")
def get_metrics():
    """
    Retrieves the trained model's performance metrics.
    """
    try:
        _, metrics = load_trained_model()
        return metrics
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Model is not trained yet. Please trigger training first.")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/sniff/start")
def start_sniffer():
    """
    Starts packet sniffing / simulation.
    """
    try:
        global_sniffer.start()
        return {"success": True, "message": "Sniffer started successfully."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/sniff/stop")
def stop_sniffer():
    """
    Stops packet sniffing / simulation.
    """
    try:
        global_sniffer.stop()
        return {"success": True, "message": "Sniffer stopped successfully."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/sniff/toggle_attacks")
def toggle_attacks(data: ToggleAttacksInput):
    """
    Toggles whether simulated attacks are generated.
    """
    try:
        global_sniffer.simulate_attacks = data.enabled
        return {"success": True, "simulate_attacks": global_sniffer.simulate_attacks}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/sniff/traffic")
def get_traffic():
    """
    Fetches recent network flows, making real-time Random Forest predictions on each.
    """
    try:
        raw_flows = global_sniffer.get_recent_flows(limit=50)
        
        # Check if model is trained
        model_trained = os.path.exists(os.path.join(os.path.dirname(__file__), '..', 'data', 'model.joblib'))
        
        processed_flows = []
        for flow in raw_flows:
            flow_copy = flow.copy()
            
            if model_trained:
                try:
                    # Preprocess and predict
                    scaled_df, _ = preprocess_single_flow(flow)
                    pred_label, probs = predict_single_flow(scaled_df)
                    
                    flow_copy['Prediction'] = pred_label
                    flow_copy['Confidence'] = probs[pred_label]
                    flow_copy['Probabilities'] = probs
                except Exception as ex:
                    flow_copy['Prediction'] = 'Error'
                    flow_copy['Confidence'] = 0.0
                    flow_copy['ErrorDetail'] = str(ex)
            else:
                flow_copy['Prediction'] = 'Model Untrained'
                flow_copy['Confidence'] = 1.0
                
            processed_flows.append(flow_copy)
            
        return {
            "flows": processed_flows,
            "sniffer_running": global_sniffer.is_running,
            "fallback_mode": global_sniffer.fallback_mode
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/analyze")
def analyze_flow(flow: Dict[str, Any]):
    """
    Analyzes a single network flow:
    1. Classifies it using the Random Forest model.
    2. Generates SHAP explainability contributions.
    3. Produces security response recommendations.
    """
    try:
        # Check if model is trained
        model_exists = os.path.exists(os.path.join(os.path.dirname(__file__), '..', 'data', 'model.joblib'))
        if not model_exists:
            raise HTTPException(status_code=400, detail="Model is not trained. Please train the model first.")
        
        # 1. Preprocess the flow
        scaled_df, raw_df = preprocess_single_flow(flow)
        
        # 2. Predict the label
        pred_label, prob_dict = predict_single_flow(scaled_df)
        
        # 3. Generate XAI (SHAP) explanations
        shap_explanation = explain_prediction(scaled_df, raw_df, target_class_label=pred_label)
        
        # 4. Fetch security recommendations
        recommendations = get_recommendations(pred_label)
        
        return {
            "prediction": pred_label,
            "confidence": prob_dict[pred_label],
            "probabilities": prob_dict,
            "explanation": shap_explanation,
            "recommendations": recommendations
        }
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Flow analysis failed: {str(e)}")

# Mount the static frontend directory.
# Note: This requires the frontend folder to exist.
FRONTEND_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'frontend'))
if os.path.exists(FRONTEND_DIR):
    app.mount("/frontend", StaticFiles(directory=FRONTEND_DIR), name="frontend")

# Serve index.html at root
@app.get("/")
def read_index():
    index_path = os.path.join(FRONTEND_DIR, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return {"message": "Welcome to XAI-IDS API. Frontend files not found yet."}
