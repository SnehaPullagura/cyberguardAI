# Unsupervised Model Evaluation

Unsupervised anomaly detection models are evaluated using:
- **Isolation Forest**: Decision score variance and mean anomaly score.
- **PyTorch Autoencoder**: MSE reconstruction loss and 95th percentile error threshold.
- **DBSCAN**: Outlier/noise ratio and number of identified dense clusters.
