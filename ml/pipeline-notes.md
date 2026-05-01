# Research-grade Pipeline Notes

Feature extraction dimensions:
- request frequency in short windows
- endpoint entropy and scan breadth
- user-agent risk and churn
- failure ratio and auth abuse indicators
- deception endpoint interaction score

Model:
- Online anomaly model with decayed statistics
- Incremental updates with persistent model state
- Confidence-driven decisions integrated into adaptive response planner

Evaluation:
- precision, recall, F1 via internal/ml ComputeMetrics
- use replay logs with labels to tune anomaly_threshold

Deployment recommendations:
1. Start in shadow mode.
2. Record false positives via API endpoint.
3. Raise confidence threshold until precision SLO is met.
4. Promote to hybrid then full block mode.
