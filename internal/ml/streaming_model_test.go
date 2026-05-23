package ml

import "testing"

func TestPredictAndLearnFlagsOutlier(t *testing.T) {
	m := NewOnlineAnomalyModel(0.55)

	for i := 0; i < 200; i++ {
		m.PredictAndLearn(FeatureVector{RequestFrequency: 0.2, EndpointEntropy: 0.5, UserAgentRisk: 0.2, ErrorRate: 0.1, BurstScore: 0.1})
	}

	pred := m.PredictAndLearn(FeatureVector{RequestFrequency: 1.0, EndpointEntropy: 0.95, UserAgentRisk: 0.9, ErrorRate: 1.0, BurstScore: 1.0, CredentialStuffing: 1.0, ScanScore: 1.0, HoneypotScore: 1.0})
	if !pred.IsAnomalous {
		t.Fatalf("expected anomalous prediction, got %+v", pred)
	}
}

func TestComputeMetrics(t *testing.T) {
	expected := []bool{true, false, true, false}
	predicted := []bool{true, false, false, false}
	m := ComputeMetrics(expected, predicted)
	if m.Precision <= 0 || m.Recall <= 0 || m.F1 <= 0 {
		t.Fatalf("unexpected metrics %+v", m)
	}
}

func TestBatchPredictAndReset(t *testing.T) {
	m := NewOnlineAnomalyModel(0.55)

	m.PredictAndLearn(FeatureVector{RequestFrequency: 0.25, EndpointEntropy: 0.4, UserAgentRisk: 0.2, ErrorRate: 0.1, BurstScore: 0.2})
	predictions := m.BatchPredict([]FeatureVector{
		{RequestFrequency: 0.3, EndpointEntropy: 0.45, UserAgentRisk: 0.25, ErrorRate: 0.1, BurstScore: 0.2},
		{RequestFrequency: 1.5, EndpointEntropy: 1.2, UserAgentRisk: -0.1, ErrorRate: 2.0, BurstScore: 1.3, HoneypotScore: 0.8},
	})

	if len(predictions) != 2 {
		t.Fatalf("expected 2 predictions, got %d", len(predictions))
	}
	if predictions[0].AnomalyScore < 0 || predictions[1].AnomalyScore < 0 {
		t.Fatalf("expected non-negative predictions, got %+v", predictions)
	}

	m.Reset()
	if pred := m.PredictAndLearn(FeatureVector{RequestFrequency: 0.4}); pred.AnomalyScore != 0 {
		t.Fatalf("expected reset model to re-seed from scratch, got %+v", pred)
	}
}
