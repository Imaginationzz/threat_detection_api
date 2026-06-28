# Threat Detection MLOps

An end-to-end MLOps project for network threat detection using Machine Learning, FastAPI, Docker, MLflow, and AWS EC2.

## Features

- Detects malicious network traffic using an Isolation Forest model.
- REST API built with FastAPI.
- Experiment tracking with MLflow.
- Dockerized application.
- Deployable on AWS EC2.
- Health monitoring endpoint.
- Interactive API documentation with Swagger UI.

## Tech Stack

- Python
- Scikit-learn
- FastAPI
- MLflow
- Docker & Docker Compose
- AWS EC2
- Pandas & NumPy

## Project Structure

```
threat-detection-mlops/
│
├── api/                # FastAPI application
├── data/               # Dataset
├── models/             # Trained models
├── notebooks/          # Model development
├── src/                # Training utilities
├── monitoring/         # Monitoring scripts
├── tests/              # Unit tests
├── mlflow.db           # MLflow tracking database
├── Dockerfile
├── docker-compose.yml
└── requirements.txt
```

## Installation

```bash
git clone <repository-url>
cd threat-detection-mlops

python -m venv mlops_env
source mlops_env/Scripts/activate   # Windows Git Bash

pip install -r requirements.txt
```

## Run the API

```bash
docker compose up --build
```

API:

```
http://localhost:8000
```

Swagger Documentation:

```
http://localhost:8000/docs
```

Health Check:

```
http://localhost:8000/health
```

## MLflow

Start the MLflow UI:

```bash
mlflow ui --backend-store-uri sqlite:///mlflow.db
```

Open:

```
http://localhost:5000
```

MLflow tracks:

- Parameters
- Metrics
- Models
- Experiments

## Deployment

The application can be deployed to AWS EC2 using Docker.

## Model Performance

| Metric | Value |
|--------|-------:|
| F1 Score | 0.9520 |
| ROC AUC | 0.9847 |

## Future Improvements

- CI/CD pipeline with GitHub Actions
- Kubernetes deployment
- Prometheus & Grafana monitoring
- Automated model retraining
- Model registry and versioning

## Author

Yezid Rahmouni
