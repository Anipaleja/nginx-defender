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
