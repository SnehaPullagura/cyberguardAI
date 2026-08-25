# Model Training Pipeline

Training and inference are strictly decoupled. Model training is triggered asynchronously via `POST /api/v1/ml/train` by authorized users (`ML_TRAIN` permission). Trained models are saved to `ML_MODEL_DIR` and registered in the database catalog via `ModelRegistryService`.
