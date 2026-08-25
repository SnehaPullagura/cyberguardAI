# DBSCAN Out-of-Sample Inference Strategy

Standard `DBSCAN` clustering does not support out-of-sample `.predict()` methods. Calling `fit_predict()` on single real-time event samples is mathematically incorrect.

## Real-Time Strategy Implemented
1. During `.fit(X)`: Compute cluster centroids and 95th percentile intra-cluster radius for each dense cluster ($label \ge 0$).
2. During `.predict(x)`: Calculate Euclidean distance from sample $x$ to nearest cluster centroid.
3. If $dist > 1.5 \times \text{radius}$, classify sample as noise outlier ($label = -1$) and assign an out-of-cluster anomaly score.
