# Isolation Forest Anomaly Detector

`IsolationForestDetector` partitions feature space using random tree splits.
Decision function raw scores are transformed using a calibrated sigmoid function:
$$\text{AnomalyScore} = \frac{1}{1 + e^{5 \cdot \text{decision\_score}}}$$
Returns normalized anomaly scores in range `[0.0, 1.0]`.
