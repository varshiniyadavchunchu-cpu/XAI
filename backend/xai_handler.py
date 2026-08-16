import os
import shap
import numpy as np
import pandas as pd
import joblib
from backend.model_handler import load_trained_model, MODEL_FILE
from backend.data_handler import get_data_splits, FEATURE_COLUMNS, DATA_DIR

EXPLAINER_BACKGROUND_FILE = os.path.join(DATA_DIR, 'explainer_background.joblib')

def get_shap_explainer():
    """
    Initializes and returns a SHAP TreeExplainer, using a saved background sample for reference.
    Trains and saves the background sample if it doesn't exist yet.
    """
    model, _ = load_trained_model()
    
    # Check if we have saved background data
    if not os.path.exists(EXPLAINER_BACKGROUND_FILE):
        print("Background data for SHAP explainer not found. Creating background sample...")
        X_train, _, _, _, _, _, _ = get_data_splits()
        # Take a subset of 100 random samples as background dataset to speed up SHAP computations
        background = shap.sample(X_train, 100, random_state=42)
        os.makedirs(DATA_DIR, exist_ok=True)
        joblib.dump(background, EXPLAINER_BACKGROUND_FILE)
    else:
        background = joblib.load(EXPLAINER_BACKGROUND_FILE)
        
    # Use TreeExplainer (optimized for tree-based models like Random Forest)
    explainer = shap.TreeExplainer(model, data=background)
    return explainer, background

def explain_prediction(scaled_flow_df, raw_flow_df, target_class_label=None):
    """
    Generates SHAP explanation for a single prediction.
    Returns:
        - base_value: The expected output score for the target class.
        - prediction_value: The model output probability for the target class.
        - contributions: List of features sorted by impact.
    """
    explainer, _ = get_shap_explainer()
    
    # Load label encoder
    from backend.data_handler import load_scaler_and_encoder
    _, label_encoder = load_scaler_and_encoder()
    
    # Predict to find the predicted label index
    from backend.model_handler import predict_single_flow
    pred_label, prob_dict = predict_single_flow(scaled_flow_df)
    
    if target_class_label is None:
        target_class_label = pred_label
        
    target_class_idx = list(label_encoder.classes_).index(target_class_label)
    
    # Calculate SHAP values for the single sample
    # shap_values is a list of arrays (one per class), or a 3D array depending on shap version
    shap_values = explainer.shap_values(scaled_flow_df)
    
    # Handle SHAP multi-class return variations
    if isinstance(shap_values, list):
        # shap_values[class_idx] has shape (num_samples, num_features)
        sample_shap = shap_values[target_class_idx][0]
    else:
        # shap_values has shape (num_samples, num_features, num_classes)
        # or (num_classes, num_samples, num_features)
        if len(shap_values.shape) == 3:
            if shap_values.shape[2] == len(label_encoder.classes_):
                sample_shap = shap_values[0, :, target_class_idx]
            else:
                sample_shap = shap_values[target_class_idx, 0, :]
        else:
            sample_shap = shap_values[0] # Fallback
            
    # Base value for the target class (TreeExplainer expected value)
    base_values = explainer.expected_value
    if isinstance(base_values, (list, np.ndarray)):
        base_value = float(base_values[target_class_idx])
    else:
        base_value = float(base_values)
        
    # Get contributions
    contributions = []
    for i, col in enumerate(FEATURE_COLUMNS):
        shap_val = float(sample_shap[i])
        raw_val = float(raw_flow_df.iloc[0][col])
        scaled_val = float(scaled_flow_df.iloc[0][col])
        
        contributions.append({
            'feature': col,
            'shap_value': shap_val,
            'raw_value': raw_val,
            'scaled_value': scaled_val,
            'abs_shap': abs(shap_val)
        })
        
    # Sort contributions by absolute SHAP value descending
    contributions = sorted(contributions, key=lambda x: x['abs_shap'], reverse=True)
    
    return {
        'target_class': target_class_label,
        'predicted_class': pred_label,
        'prediction_probability': prob_dict[target_class_label],
        'base_value': base_value,
        'contributions': contributions
    }
