# Multi-Model Ensemble Inference Pipeline

`EnsembleInferencePipeline` aggregates predictions across detectors:
$$\text{Score} = 0.40 \cdot S_{\text{IF}} + 0.40 \cdot S_{\text{AE}} + 0.20 \cdot S_{\text{DBSCAN}}$$
Returns a standardized `MLInferenceResult` including latency, model version, and feature vector metadata.
