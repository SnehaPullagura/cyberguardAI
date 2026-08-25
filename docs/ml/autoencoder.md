# PyTorch Neural Autoencoder Detector

`NeuralAutoencoderDetector` trains a deep feedforward neural network ($11 \to 16 \to 8 \to 16 \to 11$) to reconstruct normal security event feature vectors.
- Reconstruction error calculated via Mean Squared Error (MSE).
- Anomaly threshold calibrated at the 95th percentile MSE during training.
- Evaluates out-of-sample events in non-training mode (`model.eval()`).
