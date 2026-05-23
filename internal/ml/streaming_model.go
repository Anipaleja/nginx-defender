package ml

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"sync"
	"time"
)

// FeatureVector captures normalized request behavior features used by the online model.
type FeatureVector struct {
	RequestFrequency   float64 `json:"request_frequency"`
	EndpointEntropy    float64 `json:"endpoint_entropy"`
	UserAgentRisk      float64 `json:"user_agent_risk"`
	ErrorRate          float64 `json:"error_rate"`
	BurstScore         float64 `json:"burst_score"`
	CredentialStuffing float64 `json:"credential_stuffing"`
	ScanScore          float64 `json:"scan_score"`
	HoneypotScore      float64 `json:"honeypot_score"`
}

// EvaluationMetrics contains model quality metrics.
type EvaluationMetrics struct {
	Precision float64 `json:"precision"`
	Recall    float64 `json:"recall"`
	F1        float64 `json:"f1"`
	Samples   int     `json:"samples"`
}

// Prediction contains anomaly score and confidence.
type Prediction struct {
	AnomalyScore float64 `json:"anomaly_score"`
	Confidence   float64 `json:"confidence"`
	IsAnomalous  bool    `json:"is_anomalous"`
}

// OnlineAnomalyModel performs streaming anomaly detection using decayed online statistics.
type OnlineAnomalyModel struct {
	mu sync.RWMutex

	means   map[string]float64
	vars    map[string]float64
	counts  map[string]float64
	weights map[string]float64

	threshold float64
	decay     float64
	updatedAt time.Time
}

func NewOnlineAnomalyModel(threshold float64) *OnlineAnomalyModel {
	if threshold <= 0 {
		threshold = 0.68
	}

	return &OnlineAnomalyModel{
		means:  map[string]float64{},
		vars:   map[string]float64{},
		counts: map[string]float64{},
		weights: map[string]float64{
			"request_frequency":   0.19,
			"endpoint_entropy":    0.11,
			"user_agent_risk":     0.10,
			"error_rate":          0.12,
			"burst_score":         0.16,
			"credential_stuffing": 0.14,
			"scan_score":          0.12,
			"honeypot_score":      0.06,
		},
		threshold: threshold,
		decay:     0.995,
		updatedAt: time.Now(),
	}
}

func (m *OnlineAnomalyModel) PredictAndLearn(v FeatureVector) Prediction {
	m.mu.Lock()
	defer m.mu.Unlock()

	features := flatten(v)
	if len(features) == 0 {
		return Prediction{}
	}

	if len(m.means) == 0 {
		for k, val := range features {
			m.means[k] = val
			m.vars[k] = 1e-6
			m.counts[k] = 1
		}
		m.updatedAt = time.Now()
		return Prediction{AnomalyScore: 0.0, Confidence: 0.0, IsAnomalous: false}
	}

	var weighted float64
	var totalWeight float64
	for key, value := range features {
		mean := m.means[key]
		variance := m.vars[key]
		if variance < 1e-6 {
			variance = 1e-6
		}

		z := math.Abs(value-mean) / math.Sqrt(variance)
		score := math.Tanh(z / 4.0)
		w := m.weights[key]
		weighted += score * w
		totalWeight += w
	}

	if totalWeight == 0 {
		totalWeight = 1
	}

	anomaly := weighted / totalWeight
	conf := math.Min(1.0, anomaly+0.15)
	isAnomalous := anomaly >= m.threshold

	for key, value := range features {
		count := m.counts[key]*m.decay + 1.0
		mean := m.means[key]
		delta := value - mean
		mean += delta / count
		m2 := m.vars[key]*(count-1) + delta*(value-mean)
		variance := m2 / math.Max(1.0, count)
		if variance < 1e-6 {
			variance = 1e-6
		}

		m.counts[key] = count
		m.means[key] = mean
		m.vars[key] = variance
	}

	m.updatedAt = time.Now()
	return Prediction{AnomalyScore: anomaly, Confidence: conf, IsAnomalous: isAnomalous}
}

// BatchPredict scores a slice of feature vectors without mutating the model state.
func (m *OnlineAnomalyModel) BatchPredict(vectors []FeatureVector) []Prediction {
	m.mu.RLock()
	defer m.mu.RUnlock()

	predictions := make([]Prediction, 0, len(vectors))
	for _, vector := range vectors {
		predictions = append(predictions, m.predictLocked(flatten(vector)))
	}
	return predictions
}

// Reset clears learned statistics while preserving the configured weights.
func (m *OnlineAnomalyModel) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.means = map[string]float64{}
	m.vars = map[string]float64{}
	m.counts = map[string]float64{}
	m.updatedAt = time.Now()
}

func (m *OnlineAnomalyModel) Save(path string) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	payload := map[string]interface{}{
		"means":      m.means,
		"vars":       m.vars,
		"counts":     m.counts,
		"weights":    m.weights,
		"threshold":  m.threshold,
		"decay":      m.decay,
		"updated_at": m.updatedAt,
	}
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

func (m *OnlineAnomalyModel) Load(path string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	payload := struct {
		Means     map[string]float64 `json:"means"`
		Vars      map[string]float64 `json:"vars"`
		Counts    map[string]float64 `json:"counts"`
		Weights   map[string]float64 `json:"weights"`
		Threshold float64            `json:"threshold"`
		Decay     float64            `json:"decay"`
		UpdatedAt time.Time          `json:"updated_at"`
	}{}

	if err := json.Unmarshal(data, &payload); err != nil {
		return fmt.Errorf("decode model: %w", err)
	}

	m.means = payload.Means
	m.vars = payload.Vars
	m.counts = payload.Counts
	if len(payload.Weights) > 0 {
		m.weights = payload.Weights
	}
	if payload.Threshold > 0 {
		m.threshold = payload.Threshold
	}
	if payload.Decay > 0 {
		m.decay = payload.Decay
	}
	m.updatedAt = payload.UpdatedAt
	return nil
}

func flatten(v FeatureVector) map[string]float64 {
	return map[string]float64{
		"request_frequency":   sanitizeScore(v.RequestFrequency),
		"endpoint_entropy":    sanitizeScore(v.EndpointEntropy),
		"user_agent_risk":     sanitizeScore(v.UserAgentRisk),
		"error_rate":          sanitizeScore(v.ErrorRate),
		"burst_score":         sanitizeScore(v.BurstScore),
		"credential_stuffing": sanitizeScore(v.CredentialStuffing),
		"scan_score":          sanitizeScore(v.ScanScore),
		"honeypot_score":      sanitizeScore(v.HoneypotScore),
	}
}

func (m *OnlineAnomalyModel) predictLocked(features map[string]float64) Prediction {
	if len(features) == 0 || len(m.means) == 0 {
		return Prediction{}
	}

	var weighted float64
	var totalWeight float64
	for key, value := range features {
		mean := m.means[key]
		variance := m.vars[key]
		if variance < 1e-6 {
			variance = 1e-6
		}

		z := math.Abs(value-mean) / math.Sqrt(variance)
		score := math.Tanh(z / 4.0)
		w := m.weights[key]
		weighted += score * w
		totalWeight += w
	}

	if totalWeight == 0 {
		totalWeight = 1
	}

	anomaly := weighted / totalWeight
	return Prediction{AnomalyScore: anomaly, Confidence: math.Min(1.0, anomaly+0.15), IsAnomalous: anomaly >= m.threshold}
}

func sanitizeScore(value float64) float64 {
	if math.IsNaN(value) || math.IsInf(value, 0) {
		return 0
	}
	if value < 0 {
		return 0
	}
	if value > 1 {
		return 1
	}
	return value
}

func ComputeMetrics(expected, predicted []bool) EvaluationMetrics {
	var tp, fp, fn float64
	for i := 0; i < len(expected) && i < len(predicted); i++ {
		switch {
		case expected[i] && predicted[i]:
			tp++
		case !expected[i] && predicted[i]:
			fp++
		case expected[i] && !predicted[i]:
			fn++
		}
	}

	precision := safeDiv(tp, tp+fp)
	recall := safeDiv(tp, tp+fn)
	f1 := safeDiv(2*precision*recall, precision+recall)
	return EvaluationMetrics{Precision: precision, Recall: recall, F1: f1, Samples: len(expected)}
}

func safeDiv(n, d float64) float64 {
	if d == 0 {
		return 0
	}
	return n / d
}
