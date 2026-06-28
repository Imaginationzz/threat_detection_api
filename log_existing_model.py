import mlflow
import mlflow.sklearn
import joblib

mlflow.set_tracking_uri("sqlite:///mlflow.db")
mlflow.set_experiment("threat_detection")

model = joblib.load("models/isolation_forest.pkl")  # adjust filename if different

with mlflow.start_run(run_name="isolation_forest_v1_recovered"):
    mlflow.log_param("model_type", "IsolationForest")
    mlflow.log_metric("f1", 0.9520)
    mlflow.log_metric("auc", 0.9847)
    mlflow.sklearn.log_model(model, "model")