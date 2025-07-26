package detector

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"sync"
	"time"

	"github.com/Anipaleja/nginx-defender/internal/config"
)

// MLModel represents a machine learning model for threat detection
type MLModel struct {
	config     config.MLConfig
	features   []string
	weights    []float64
	threshold  float64
	scaler     *FeatureScaler
	mutex      sync.RWMutex
	
	// Training data
	trainingData []TrainingExample
	lastUpdate   time.Time
}

// TrainingExample represents a training example
type TrainingExample struct {
	Features []float64 `json:"features"`
	Label    int       `json:"label"` // 0 = benign, 1 = threat
	Weight   float64   `json:"weight"`
}

// Prediction represents a model prediction
type Prediction struct {
	IsThreat   bool    `json:"is_threat"`
	Confidence float64 `json:"confidence"`
	ThreatType string  `json:"threat_type"`
}

// FeatureScaler normalizes features
type FeatureScaler struct {
	Means []float64 `json:"means"`
	Stds  []float64 `json:"stds"`
}

// NewMLModel creates a new ML model
func NewMLModel(cfg config.MLConfig) (*MLModel, error) {
	model := &MLModel{
		config:       cfg,
		threshold:    cfg.AnomalyThreshold,
		trainingData: []TrainingExample{},
		lastUpdate:   time.Now(),
	}
	
	// Initialize feature names
	model.features = []string{
		"path_length", "query_length", "ua_length", "response_code",
		"request_rate", "unique_endpoints", "failed_requests_ratio",
		"is_bot", "has_suspicious_patterns", "country_risk_score",
		"time_of_day", "request_method_score", "content_type_score",
		"referrer_score", "ssl_score", "port_score", "protocol_score",
		"header_count", "unusual_headers", "payload_size",
	}
	
	// Initialize weights (simple linear model)
	model.weights = make([]float64, len(model.features))
	for i := range model.weights {
		model.weights[i] = 0.1 // Start with small random weights
	}
	
	// Initialize feature scaler
	model.scaler = &FeatureScaler{
		Means: make([]float64, len(model.features)),
		Stds:  make([]float64, len(model.features)),
	}
	
	// Load existing model if available
	if cfg.ModelPath != "" {
		if err := model.loadModel(cfg.ModelPath); err != nil {
			return nil, fmt.Errorf("failed to load ML model: %v", err)
		}
	}
	
	// Start update routine
	go model.updateRoutine()
	
	return model, nil
}

// Predict makes a prediction for given features
func (m *MLModel) Predict(features []float64) Prediction {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	
	if len(features) != len(m.weights) {
		return Prediction{IsThreat: false, Confidence: 0.0}
	}
	
	// Scale features
	scaledFeatures := m.scaler.Transform(features)
	
	// Calculate linear combination
	score := 0.0
	for i, feature := range scaledFeatures {
		score += feature * m.weights[i]
	}
	
	// Apply sigmoid activation
	confidence := 1.0 / (1.0 + math.Exp(-score))
	
	// Determine threat type based on feature importance
	threatType := m.determineThreatType(features)
	
	return Prediction{
		IsThreat:   confidence > m.threshold,
		Confidence: confidence,
		ThreatType: threatType,
	}
}

// AddTrainingExample adds a new training example
func (m *MLModel) AddTrainingExample(features []float64, isThreat bool) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	
	label := 0
	if isThreat {
		label = 1
	}
	
	example := TrainingExample{
		Features: features,
		Label:    label,
		Weight:   1.0,
	}
	
	m.trainingData = append(m.trainingData, example)
	
	// Keep only recent training data
	maxExamples := 10000
	if len(m.trainingData) > maxExamples {
		m.trainingData = m.trainingData[len(m.trainingData)-maxExamples:]
	}
}

// Train updates the model with current training data
func (m *MLModel) Train() error {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	
	if len(m.trainingData) < 100 {
		return fmt.Errorf("insufficient training data: %d examples", len(m.trainingData))
	}
	
	// Update feature scaler
	m.updateScaler()
	
	// Simple gradient descent
	learningRate := 0.01
	epochs := 100
	
	for epoch := 0; epoch < epochs; epoch++ {
		for _, example := range m.trainingData {
			// Forward pass
			scaledFeatures := m.scaler.Transform(example.Features)
			score := 0.0
			for i, feature := range scaledFeatures {
				score += feature * m.weights[i]
			}
			
			prediction := 1.0 / (1.0 + math.Exp(-score))
			error := float64(example.Label) - prediction
			
			// Backward pass
			for i, feature := range scaledFeatures {
				m.weights[i] += learningRate * error * feature * example.Weight
			}
		}
	}
	
	m.lastUpdate = time.Now()
	return nil
}

// updateScaler updates the feature scaler with current training data
func (m *MLModel) updateScaler() {
	if len(m.trainingData) == 0 {
		return
	}
	
	numFeatures := len(m.features)
	
	// Calculate means
	for i := 0; i < numFeatures; i++ {
		sum := 0.0
		for _, example := range m.trainingData {
			if i < len(example.Features) {
				sum += example.Features[i]
			}
		}
		m.scaler.Means[i] = sum / float64(len(m.trainingData))
	}
	
	// Calculate standard deviations
	for i := 0; i < numFeatures; i++ {
		sumSquares := 0.0
		for _, example := range m.trainingData {
			if i < len(example.Features) {
				diff := example.Features[i] - m.scaler.Means[i]
				sumSquares += diff * diff
			}
		}
		variance := sumSquares / float64(len(m.trainingData))
		m.scaler.Stds[i] = math.Sqrt(variance)
		
		// Avoid division by zero
		if m.scaler.Stds[i] == 0 {
			m.scaler.Stds[i] = 1.0
		}
	}
}

// Transform scales features using the scaler
func (s *FeatureScaler) Transform(features []float64) []float64 {
	scaled := make([]float64, len(features))
	for i, feature := range features {
		if i < len(s.Means) && i < len(s.Stds) {
			scaled[i] = (feature - s.Means[i]) / s.Stds[i]
		} else {
			scaled[i] = feature
		}
	}
	return scaled
}

// determineThreatType determines threat type based on feature values
func (m *MLModel) determineThreatType(features []float64) string {
	// Simple heuristic based on feature importance
	if len(features) < 5 {
		return "unknown"
	}
	
	// Check for different threat types based on feature patterns
	pathLength := features[0]
	queryLength := features[1]
	requestRate := features[4]
	failedRatio := features[6]
	isBot := features[7]
	
	if requestRate > 10 {
		return "ddos"
	}
	
	if failedRatio > 0.5 {
		return "brute_force"
	}
	
	if pathLength > 100 || queryLength > 200 {
		return "injection_attack"
	}
	
	if isBot > 0.5 {
		return "bot_attack"
	}
	
	return "anomalous_behavior"
}

// updateRoutine periodically updates the model
func (m *MLModel) updateRoutine() {
	ticker := time.NewTicker(time.Duration(m.config.UpdateInterval) * time.Second)
	defer ticker.Stop()
	
	for range ticker.C {
		if time.Since(m.lastUpdate) > time.Duration(m.config.UpdateInterval)*time.Second {
			if err := m.Train(); err != nil {
				// Log error but continue
				continue
			}
			
			// Save model
			if m.config.ModelPath != "" {
				m.saveModel(m.config.ModelPath)
			}
		}
	}
}

// saveModel saves the model to disk
func (m *MLModel) saveModel(path string) error {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	
	modelData := struct {
		Features []string      `json:"features"`
		Weights  []float64     `json:"weights"`
		Scaler   *FeatureScaler `json:"scaler"`
		LastUpdate time.Time   `json:"last_update"`
	}{
		Features:   m.features,
		Weights:    m.weights,
		Scaler:     m.scaler,
		LastUpdate: m.lastUpdate,
	}
	
	data, err := json.MarshalIndent(modelData, "", "  ")
	if err != nil {
		return err
	}
	
	return os.WriteFile(path, data, 0644)
}

// loadModel loads the model from disk
func (m *MLModel) loadModel(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	
	var modelData struct {
		Features []string      `json:"features"`
		Weights  []float64     `json:"weights"`
		Scaler   *FeatureScaler `json:"scaler"`
		LastUpdate time.Time   `json:"last_update"`
	}
	
	if err := json.Unmarshal(data, &modelData); err != nil {
		return err
	}
	
	m.mutex.Lock()
	defer m.mutex.Unlock()
	
	m.features = modelData.Features
	m.weights = modelData.Weights
	m.scaler = modelData.Scaler
	m.lastUpdate = modelData.LastUpdate
	
	return nil
}

// GetModelStats returns statistics about the model
func (m *MLModel) GetModelStats() map[string]interface{} {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	
	return map[string]interface{}{
		"num_features":     len(m.features),
		"training_examples": len(m.trainingData),
		"last_update":      m.lastUpdate,
		"threshold":        m.threshold,
	}
}
