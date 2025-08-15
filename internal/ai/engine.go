package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/Anipaleja/nginx-defender/internal/types"
)

// AI Engine for next-generation threat detection
// This surpasses CrowdSec and ModSecurity with advanced ML capabilities

// ThreatDetectionEngine represents the core AI engine
type ThreatDetectionEngine struct {
	models          map[string]Model
	threatIntel     *ThreatIntelligence
	behaviorEngine  *BehaviorAnalyzer
	federatedClient *FederatedLearningClient
	logger          *logrus.Logger
	mutex           sync.RWMutex
	
	// Performance metrics
	stats *EngineStats
}

// Model represents an AI/ML model for threat detection
type Model interface {
	Predict(input *InputVector) (*Prediction, error)
	Update(trainingData []*TrainingExample) error
	GetAccuracy() float64
	GetVersion() string
}

// InputVector represents input data for AI models
type InputVector struct {
	Features map[string]interface{} `json:"features"`
	Metadata map[string]string      `json:"metadata"`
	
	// Request context
	RequestData *RequestData `json:"request_data"`
	
	// Network context
	NetworkData *NetworkData `json:"network_data"`
	
	// Behavioral context
	BehaviorData *BehaviorData `json:"behavior_data"`
}

// RequestData contains HTTP request information
type RequestData struct {
	Method     string            `json:"method"`
	URL        string            `json:"url"`
	Headers    map[string]string `json:"headers"`
	Body       string            `json:"body"`
	UserAgent  string            `json:"user_agent"`
	ContentType string           `json:"content_type"`
	Size       int64             `json:"size"`
	Timestamp  time.Time         `json:"timestamp"`
}

// NetworkData contains network-level information
type NetworkData struct {
	SourceIP       string    `json:"source_ip"`
	DestinationIP  string    `json:"destination_ip"`
	SourcePort     int       `json:"source_port"`
	DestinationPort int      `json:"destination_port"`
	Protocol       string    `json:"protocol"`
	GeoLocation    *GeoInfo  `json:"geo_location"`
	ASN            *ASNInfo  `json:"asn"`
	TLSFingerprint string    `json:"tls_fingerprint"`
}

// BehaviorData contains behavioral analysis information
type BehaviorData struct {
	SessionID        string                 `json:"session_id"`
	RequestSequence  []string              `json:"request_sequence"`
	TimingPatterns   []time.Duration       `json:"timing_patterns"`
	InteractionDepth int                   `json:"interaction_depth"`
	MouseMovements   []MouseEvent          `json:"mouse_movements"`
	KeyboardTimings  []KeyboardEvent       `json:"keyboard_timings"`
	DeviceFingerprint *DeviceFingerprint   `json:"device_fingerprint"`
}

// GeoInfo contains geographical information
type GeoInfo struct {
	Country     string  `json:"country"`
	Region      string  `json:"region"`
	City        string  `json:"city"`
	Latitude    float64 `json:"latitude"`
	Longitude   float64 `json:"longitude"`
	ISP         string  `json:"isp"`
	Organization string `json:"organization"`
	Timezone    string  `json:"timezone"`
}

// ASNInfo contains Autonomous System Number information
type ASNInfo struct {
	Number       int    `json:"number"`
	Organization string `json:"organization"`
	Description  string `json:"description"`
	Country      string `json:"country"`
}

// MouseEvent represents mouse movement data
type MouseEvent struct {
	X         int           `json:"x"`
	Y         int           `json:"y"`
	Timestamp time.Time     `json:"timestamp"`
	Button    int           `json:"button"`
	Type      string        `json:"type"` // move, click, scroll
	Velocity  float64       `json:"velocity"`
	Pressure  float64       `json:"pressure"`
}

// KeyboardEvent represents keyboard interaction data
type KeyboardEvent struct {
	Key       string        `json:"key"`
	Timestamp time.Time     `json:"timestamp"`
	Duration  time.Duration `json:"duration"`
	Type      string        `json:"type"` // keydown, keyup
}

// DeviceFingerprint contains device identification data
type DeviceFingerprint struct {
	UserAgent       string            `json:"user_agent"`
	ScreenResolution string           `json:"screen_resolution"`
	Timezone        string            `json:"timezone"`
	Language        string            `json:"language"`
	Plugins         []string          `json:"plugins"`
	Fonts           []string          `json:"fonts"`
	Canvas          string            `json:"canvas"`
	WebGL           string            `json:"webgl"`
	AudioContext    string            `json:"audio_context"`
	ClientRects     map[string]string `json:"client_rects"`
}

// Prediction represents the output of AI model prediction
type Prediction struct {
	ThreatScore     float64                `json:"threat_score"`
	Confidence      float64                `json:"confidence"`
	ThreatTypes     []string               `json:"threat_types"`
	Recommendations []string               `json:"recommendations"`
	Explanation     *ExplanationData       `json:"explanation"`
	ModelVersion    string                 `json:"model_version"`
	ProcessingTime  time.Duration          `json:"processing_time"`
	Features        map[string]float64     `json:"features"`
}

// ExplanationData provides explainable AI results
type ExplanationData struct {
	TopFeatures     []FeatureImportance `json:"top_features"`
	DecisionPath    []DecisionNode      `json:"decision_path"`
	Counterfactuals []string           `json:"counterfactuals"`
	SimilarCases    []string           `json:"similar_cases"`
}

// FeatureImportance represents the importance of a feature in the decision
type FeatureImportance struct {
	Feature    string  `json:"feature"`
	Importance float64 `json:"importance"`
	Value      string  `json:"value"`
}

// DecisionNode represents a node in the decision tree explanation
type DecisionNode struct {
	Feature   string  `json:"feature"`
	Threshold float64 `json:"threshold"`
	Direction string  `json:"direction"` // left, right
	Samples   int     `json:"samples"`
}

// EngineStats contains performance statistics
type EngineStats struct {
	TotalPredictions     uint64        `json:"total_predictions"`
	AveragePredictionTime time.Duration `json:"average_prediction_time"`
	ThreatDetectionRate  float64       `json:"threat_detection_rate"`
	FalsePositiveRate    float64       `json:"false_positive_rate"`
	ModelAccuracy        float64       `json:"model_accuracy"`
	LastUpdate           time.Time     `json:"last_update"`
}

// TransformerModel implements advanced transformer-based threat detection
type TransformerModel struct {
	modelPath     string
	config        *TransformerConfig
	tokenizer     *Tokenizer
	attention     *AttentionMechanism
	embeddings    *EmbeddingLayer
	accuracy      float64
	version       string
	mutex         sync.RWMutex
}

// TransformerConfig contains transformer model configuration
type TransformerConfig struct {
	VocabSize      int     `json:"vocab_size"`
	HiddenSize     int     `json:"hidden_size"`
	NumLayers      int     `json:"num_layers"`
	NumHeads       int     `json:"num_heads"`
	MaxSeqLength   int     `json:"max_seq_length"`
	DropoutRate    float64 `json:"dropout_rate"`
	LearningRate   float64 `json:"learning_rate"`
	BatchSize      int     `json:"batch_size"`
}

// BehaviorAnalyzer performs advanced behavioral analysis
type BehaviorAnalyzer struct {
	graphNN       *GraphNeuralNetwork
	timeSeriesModel *types.TimeSeriesModel
	anomalyDetector *types.AnomalyDetector
	sessionStore   *types.SessionStore
	logger         *logrus.Logger
}

// GraphNeuralNetwork for analyzing user behavior graphs
type GraphNeuralNetwork struct {
	nodes        map[string]*BehaviorNode
	edges        map[string][]*BehaviorEdge
	embeddings   map[string][]float64
	messagePass  *types.MessagePassing
	aggregation  *types.GraphAggregation
}

// BehaviorNode represents a node in the behavior graph
type BehaviorNode struct {
	ID         string                 `json:"id"`
	Type       string                 `json:"type"` // user, session, request, resource
	Features   map[string]float64     `json:"features"`
	Timestamp  time.Time              `json:"timestamp"`
	Metadata   map[string]interface{} `json:"metadata"`
}

// BehaviorEdge represents an edge in the behavior graph
type BehaviorEdge struct {
	Source      string                 `json:"source"`
	Target      string                 `json:"target"`
	Type        string                 `json:"type"` // accesses, follows, contains
	Weight      float64                `json:"weight"`
	Features    map[string]float64     `json:"features"`
	Timestamp   time.Time              `json:"timestamp"`
}

// ThreatIntelligence manages global threat intelligence
type ThreatIntelligence struct {
	feeds        map[string]*ThreatFeed
	correlator   *types.ThreatCorrelator
	cache        *types.ThreatCache
	reputation   *types.ReputationEngine
	iocMatcher   *types.IOCMatcher
	logger       *logrus.Logger
}

// ThreatFeed represents a threat intelligence feed
type ThreatFeed struct {
	Name         string            `json:"name"`
	URL          string            `json:"url"`
	Format       string            `json:"format"`
	Priority     int               `json:"priority"`
	LastUpdate   time.Time         `json:"last_update"`
	UpdateInterval time.Duration   `json:"update_interval"`
	Indicators   []*ThreatIndicator `json:"indicators"`
	Metadata     map[string]string `json:"metadata"`
}

// ThreatIndicator represents a threat indicator
type ThreatIndicator struct {
	Type        string    `json:"type"` // ip, domain, hash, url, email
	Value       string    `json:"value"`
	Confidence  float64   `json:"confidence"`
	Severity    string    `json:"severity"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	Source      string    `json:"source"`
	Tags        []string  `json:"tags"`
	Description string    `json:"description"`
	TTL         time.Duration `json:"ttl"`
}

// FederatedLearningClient handles federated learning with global network
type FederatedLearningClient struct {
	serverURL      string
	nodeID         string
	localModel     Model
	globalModel    Model
	updateInterval time.Duration
	privacyEngine  *PrivacyEngine
	aggregator     *ModelAggregator
	logger         *logrus.Logger
}

// PrivacyEngine ensures privacy-preserving machine learning
type PrivacyEngine struct {
	differentialPrivacy *types.DifferentialPrivacy
	homomorphicCrypto  *types.HomomorphicEncryption
	secureMPC          *types.SecureMultiPartyComputation
	noiseGenerator     *types.NoiseGenerator
}

// NewThreatDetectionEngine creates a new AI threat detection engine
func NewThreatDetectionEngine(config *AIConfig, logger *logrus.Logger) (*ThreatDetectionEngine, error) {
	engine := &ThreatDetectionEngine{
		models:  make(map[string]Model),
		logger:  logger,
		stats:   &EngineStats{},
	}
	
	// Initialize transformer model for threat detection
	transformer, err := NewTransformerModel(config.Models.ThreatDetection)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize transformer model: %w", err)
	}
	engine.models["threat_detection"] = transformer
	
	// Initialize behavior analyzer
	behaviorAnalyzer, err := NewBehaviorAnalyzer(config.Models.BehavioralAnalysis, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize behavior analyzer: %w", err)
	}
	engine.behaviorEngine = behaviorAnalyzer
	
	// Initialize threat intelligence
	threatIntel, err := NewThreatIntelligence(config.ThreatIntel, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize threat intelligence: %w", err)
	}
	engine.threatIntel = threatIntel
	
	// Initialize federated learning client
	if config.FederatedLearning.Enabled {
		fedClient, err := NewFederatedLearningClient(config.FederatedLearning, logger)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize federated learning: %w", err)
		}
		engine.federatedClient = fedClient
	}
	
	logger.Info("Advanced AI threat detection engine initialized successfully")
	return engine, nil
}

// AnalyzeThreat performs comprehensive threat analysis using multiple AI models
func (e *ThreatDetectionEngine) AnalyzeThreat(ctx context.Context, input *InputVector) (*ComprehensiveThreatAnalysis, error) {
	startTime := time.Now()
	
	e.mutex.RLock()
	defer e.mutex.RUnlock()
	
	analysis := &ComprehensiveThreatAnalysis{
		RequestID:   input.Metadata["request_id"],
		Timestamp:   time.Now(),
		InputVector: input,
		Predictions: make(map[string]*Prediction),
	}
	
	// Run threat detection model
	if model, exists := e.models["threat_detection"]; exists {
		prediction, err := model.Predict(input)
		if err != nil {
			e.logger.WithError(err).Error("Threat detection model prediction failed")
		} else {
			analysis.Predictions["threat_detection"] = prediction
		}
	}
	
	// Run behavioral analysis
	if e.behaviorEngine != nil {
		behaviorAnalysis, err := e.behaviorEngine.AnalyzeBehavior(ctx, input.BehaviorData)
		if err != nil {
			e.logger.WithError(err).Error("Behavioral analysis failed")
		} else {
			analysis.BehaviorAnalysis = behaviorAnalysis
		}
	}
	
	// Check threat intelligence
	if e.threatIntel != nil {
		intelResults, err := e.threatIntel.CheckIndicators(ctx, input)
		if err != nil {
			e.logger.WithError(err).Error("Threat intelligence check failed")
		} else {
			analysis.ThreatIntelligence = intelResults
		}
	}
	
	// Aggregate results and calculate final threat score
	analysis.FinalThreatScore = e.calculateAggregatedThreatScore(analysis)
	analysis.ProcessingTime = time.Since(startTime)
	
	// Update statistics
	e.updateStats(analysis)
	
	// Log high-risk detections
	if analysis.FinalThreatScore > 0.8 {
		e.logger.WithFields(logrus.Fields{
			"request_id":    analysis.RequestID,
			"threat_score":  analysis.FinalThreatScore,
			"source_ip":     input.NetworkData.SourceIP,
			"user_agent":    input.RequestData.UserAgent,
		}).Warn("High-risk threat detected")
	}
	
	return analysis, nil
}

// ComprehensiveThreatAnalysis contains the complete analysis results
type ComprehensiveThreatAnalysis struct {
	RequestID          string                    `json:"request_id"`
	Timestamp          time.Time                 `json:"timestamp"`
	InputVector        *InputVector              `json:"input_vector"`
	Predictions        map[string]*Prediction    `json:"predictions"`
	BehaviorAnalysis   *BehaviorAnalysisResult   `json:"behavior_analysis"`
	ThreatIntelligence *ThreatIntelligenceResult `json:"threat_intelligence"`
	FinalThreatScore   float64                   `json:"final_threat_score"`
	ProcessingTime     time.Duration             `json:"processing_time"`
	Recommendations    []ActionRecommendation    `json:"recommendations"`
}

// BehaviorAnalysisResult contains behavioral analysis results
type BehaviorAnalysisResult struct {
	AnomalyScore       float64            `json:"anomaly_score"`
	BehaviorPatterns   []BehaviorPattern  `json:"behavior_patterns"`
	SessionRisk        float64            `json:"session_risk"`
	DeviceRisk         float64            `json:"device_risk"`
	TemporalAnomalies  []TemporalAnomaly  `json:"temporal_anomalies"`
	GraphAnalysis      *GraphAnalysisResult `json:"graph_analysis"`
}

// BehaviorPattern represents identified behavior patterns
type BehaviorPattern struct {
	Type        string  `json:"type"`
	Confidence  float64 `json:"confidence"`
	Description string  `json:"description"`
	Indicators  []string `json:"indicators"`
}

// TemporalAnomaly represents time-based anomalies
type TemporalAnomaly struct {
	Type        string    `json:"type"`
	Timestamp   time.Time `json:"timestamp"`
	Severity    string    `json:"severity"`
	Description string    `json:"description"`
}

// GraphAnalysisResult contains graph neural network analysis
type GraphAnalysisResult struct {
	NodeEmbedding     []float64             `json:"node_embedding"`
	CommunityDetection []string             `json:"community_detection"`
	AnomalousEdges    []*BehaviorEdge       `json:"anomalous_edges"`
	CentralityScores  map[string]float64    `json:"centrality_scores"`
}

// ThreatIntelligenceResult contains threat intelligence findings
type ThreatIntelligenceResult struct {
	MatchedIndicators []MatchedIndicator    `json:"matched_indicators"`
	ReputationScore   float64               `json:"reputation_score"`
	RiskLevel         string                `json:"risk_level"`
	Sources           []string              `json:"sources"`
	Correlations      []ThreatCorrelation   `json:"correlations"`
}

// MatchedIndicator represents a matched threat indicator
type MatchedIndicator struct {
	Indicator   *ThreatIndicator `json:"indicator"`
	MatchType   string           `json:"match_type"`
	Confidence  float64          `json:"confidence"`
	Context     string           `json:"context"`
}

// ThreatCorrelation represents correlated threat data
type ThreatCorrelation struct {
	Type        string    `json:"type"`
	Score       float64   `json:"score"`
	Description string    `json:"description"`
	Timestamp   time.Time `json:"timestamp"`
}

// ActionRecommendation suggests actions based on analysis
type ActionRecommendation struct {
	Action      string            `json:"action"`
	Confidence  float64           `json:"confidence"`
	Reasoning   string            `json:"reasoning"`
	Parameters  map[string]string `json:"parameters"`
	Priority    int               `json:"priority"`
}

// calculateAggregatedThreatScore combines all analysis results into final score
func (e *ThreatDetectionEngine) calculateAggregatedThreatScore(analysis *ComprehensiveThreatAnalysis) float64 {
	weights := map[string]float64{
		"threat_detection":      0.4,
		"behavior_analysis":     0.3,
		"threat_intelligence":   0.2,
		"zero_day_detection":    0.1,
	}
	
	var weightedSum float64
	var totalWeight float64
	
	// Threat detection model score
	if pred, exists := analysis.Predictions["threat_detection"]; exists {
		weightedSum += pred.ThreatScore * weights["threat_detection"]
		totalWeight += weights["threat_detection"]
	}
	
	// Behavioral analysis score
	if analysis.BehaviorAnalysis != nil {
		weightedSum += analysis.BehaviorAnalysis.AnomalyScore * weights["behavior_analysis"]
		totalWeight += weights["behavior_analysis"]
	}
	
	// Threat intelligence score
	if analysis.ThreatIntelligence != nil {
		score := 1.0 - analysis.ThreatIntelligence.ReputationScore // Convert reputation to risk
		weightedSum += score * weights["threat_intelligence"]
		totalWeight += weights["threat_intelligence"]
	}
	
	if totalWeight == 0 {
		return 0
	}
	
	return math.Min(1.0, weightedSum/totalWeight)
}

// updateStats updates engine performance statistics
func (e *ThreatDetectionEngine) updateStats(analysis *ComprehensiveThreatAnalysis) {
	e.stats.TotalPredictions++
	
	// Update average prediction time
	if e.stats.TotalPredictions == 1 {
		e.stats.AveragePredictionTime = analysis.ProcessingTime
	} else {
		// Exponentially weighted moving average
		alpha := 0.1
		e.stats.AveragePredictionTime = time.Duration(
			float64(e.stats.AveragePredictionTime)*(1-alpha) +
			float64(analysis.ProcessingTime)*alpha,
		)
	}
	
	e.stats.LastUpdate = time.Now()
}

// GetStats returns current engine statistics
func (e *ThreatDetectionEngine) GetStats() *EngineStats {
	e.mutex.RLock()
	defer e.mutex.RUnlock()
	
	// Create a copy to avoid race conditions
	stats := *e.stats
	return &stats
}

// UpdateModels updates AI models with new training data
func (e *ThreatDetectionEngine) UpdateModels(ctx context.Context, trainingData []*TrainingExample) error {
	e.mutex.Lock()
	defer e.mutex.Unlock()
	
	for name, model := range e.models {
		if err := model.Update(trainingData); err != nil {
			e.logger.WithError(err).Errorf("Failed to update model %s", name)
			continue
		}
		
		e.logger.Infof("Successfully updated model %s, new accuracy: %.4f", 
			name, model.GetAccuracy())
	}
	
	// Sync with federated learning if enabled
	if e.federatedClient != nil {
		if err := e.federatedClient.SyncModels(ctx); err != nil {
			e.logger.WithError(err).Error("Failed to sync with federated learning")
		}
	}
	
	return nil
}

// TrainingExample represents a training example for model updates
type TrainingExample struct {
	Input  *InputVector `json:"input"`
	Output *Prediction  `json:"output"`
	Label  string       `json:"label"` // threat, benign
}

// AIConfig represents AI engine configuration
type AIConfig struct {
	Models struct {
		ThreatDetection    *ModelConfig `yaml:"threat_detection"`
		BehavioralAnalysis *ModelConfig `yaml:"behavioral_analysis"`
		ZeroDayDetection   *ModelConfig `yaml:"zero_day_detection"`
	} `yaml:"models"`
	
	ThreatIntel struct {
		Enabled bool                    `yaml:"enabled"`
		Feeds   []*ThreatFeedConfig     `yaml:"feeds"`
	} `yaml:"threat_intel"`
	
	FederatedLearning struct {
		Enabled   bool   `yaml:"enabled"`
		ServerURL string `yaml:"server_url"`
		NodeID    string `yaml:"node_id"`
	} `yaml:"federated_learning"`
}

// ModelConfig represents configuration for an AI model
type ModelConfig struct {
	ModelPath          string  `yaml:"model_path"`
	ConfidenceThreshold float64 `yaml:"confidence_threshold"`
	BatchSize          int     `yaml:"batch_size"`
	GPUAcceleration    bool    `yaml:"gpu_acceleration"`
}

// ThreatFeedConfig represents threat feed configuration
type ThreatFeedConfig struct {
	Name           string        `yaml:"name"`
	URL            string        `yaml:"url"`
	Format         string        `yaml:"format"`
	UpdateInterval time.Duration `yaml:"update_interval"`
	Priority       int           `yaml:"priority"`
}
