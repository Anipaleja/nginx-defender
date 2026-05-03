# ML Pipeline

This directory contains the production ML pipeline artifacts for nginx-defender.

Components:
- Streaming online anomaly detector (internal/ml)
- Feature extraction from behavioral profiles and log metadata
- Incremental model persistence (JSON model state)
- Evaluation metrics: precision, recall, F1

Model operation modes:
- Rule-only: machine_learning.enabled = false
- ML-assisted: machine_learning.enabled = true and detection.mode = block/shadow/monitor

Operational workflow:
1. Start in shadow mode to collect baseline behavior.
2. Evaluate precision/recall from replayed logs.
3. Promote to block mode when F1 reaches your target SLO.
4. Keep incremental updates enabled for concept drift.
