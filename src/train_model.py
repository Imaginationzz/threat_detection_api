"""
Train anomaly detection models:
1. Isolation Forest
2. Autoencoder (Neural Network)

This script will:
- Load network logs
- Extract features
- Train models
- Evaluate on test set
- Track with MLflow
- Save trained models
"""

import pandas as pd
import numpy as np
import logging
from pathlib import Path

# ML libraries
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    roc_auc_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report
)

import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import layers

# MLflow tracking
import mlflow
import mlflow.sklearn
import mlflow.keras

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

print("✓ All imports successful!")

