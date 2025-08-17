package types

import (
	"time"
)

// Time series data types
type TimeSeriesPoint struct {
	Timestamp time.Time              `json:"timestamp"`
	Value     float64                `json:"value"`
	Metadata  map[string]interface{} `json:"metadata"`
}

type ForecastPoint struct {
	Timestamp  time.Time `json:"timestamp"`
	Value      float64   `json:"value"`
	Confidence float64   `json:"confidence"`
	Lower      float64   `json:"lower"`
	Upper      float64   `json:"upper"`
}

// Additional missing types for AI package
type TimeSeriesModel struct {
	Name       string                 `json:"name"`
	Type       string                 `json:"type"`
	Parameters map[string]interface{} `json:"parameters"`
	Config     map[string]interface{} `json:"config"`
}

type GradientBoostingModel struct {
	Trees       []*DecisionTree        `json:"trees"`
	Parameters  map[string]interface{} `json:"parameters"`
	Data        []*TimeSeriesPoint     `json:"data"`
	Forecast    []*ForecastPoint       `json:"forecast"`
	Accuracy    float64                `json:"accuracy"`
	LastTrained time.Time              `json:"last_trained"`
}

type AnomalyDetector struct {
	Algorithm   string                 `json:"algorithm"`
	Threshold   float64                `json:"threshold"`
	Sensitivity float64                `json:"sensitivity"`
	Models      map[string]interface{} `json:"models"`
	Config      map[string]interface{} `json:"config"`
}

type SessionStore struct {
	Sessions    map[string]*UserSession `json:"sessions"`
	MaxSessions int                     `json:"max_sessions"`
	TTL         time.Duration           `json:"ttl"`
	Storage     string                  `json:"storage"`
}

type MessagePassing struct {
	Algorithm   string                 `json:"algorithm"`
	Iterations  int                    `json:"iterations"`
	Aggregation string                 `json:"aggregation"`
	Config      map[string]interface{} `json:"config"`
}

type GraphAggregation struct {
	Method     string                 `json:"method"`
	Pooling    string                 `json:"pooling"`
	Dimensions int                    `json:"dimensions"`
	Config     map[string]interface{} `json:"config"`
}

type ThreatCorrelator struct {
	Rules      []*CorrelationRule     `json:"rules"`
	Threshold  float64                `json:"threshold"`
	TimeWindow time.Duration          `json:"time_window"`
	Config     map[string]interface{} `json:"config"`
}

type CorrelationRule struct {
	ID        string  `json:"id"`
	Name      string  `json:"name"`
	Condition string  `json:"condition"`
	Score     float64 `json:"score"`
	Enabled   bool    `json:"enabled"`
}

type ThreatCache struct {
	Entries    map[string]*ThreatEntry `json:"entries"`
	MaxEntries int                     `json:"max_entries"`
	TTL        time.Duration           `json:"ttl"`
	HitRate    float64                 `json:"hit_rate"`
}

type ThreatEntry struct {
	ID        string                 `json:"id"`
	Type      string                 `json:"type"`
	Value     string                 `json:"value"`
	Score     float64                `json:"score"`
	Source    string                 `json:"source"`
	Timestamp time.Time              `json:"timestamp"`
	Metadata  map[string]interface{} `json:"metadata"`
}

type ReputationEngine struct {
	Sources   []string               `json:"sources"`
	Weights   map[string]float64     `json:"weights"`
	Threshold float64                `json:"threshold"`
	Config    map[string]interface{} `json:"config"`
}

type IOCMatcher struct {
	Patterns  map[string]*IOCPattern `json:"patterns"`
	Threshold float64                `json:"threshold"`
	Config    map[string]interface{} `json:"config"`
}

type IOCPattern struct {
	Type       string    `json:"type"`
	Pattern    string    `json:"pattern"`
	Confidence float64   `json:"confidence"`
	Source     string    `json:"source"`
	CreatedAt  time.Time `json:"created_at"`
}

type DifferentialPrivacy struct {
	Epsilon     float64                `json:"epsilon"`
	Delta       float64                `json:"delta"`
	Sensitivity float64                `json:"sensitivity"`
	Mechanism   string                 `json:"mechanism"`
	Config      map[string]interface{} `json:"config"`
}

type HomomorphicEncryption struct {
	Scheme     string                 `json:"scheme"`
	KeySize    int                    `json:"key_size"`
	PublicKey  string                 `json:"public_key"`
	PrivateKey string                 `json:"private_key"`
	Config     map[string]interface{} `json:"config"`
}

type SecureMultiPartyComputation struct {
	Protocol  string                 `json:"protocol"`
	Parties   []string               `json:"parties"`
	Threshold int                    `json:"threshold"`
	Config    map[string]interface{} `json:"config"`
}

type NoiseGenerator struct {
	Type       string                 `json:"type"`
	Parameters map[string]float64     `json:"parameters"`
	Seed       int64                  `json:"seed"`
	Config     map[string]interface{} `json:"config"`
}

// AI/ML model types

// Missing types for Protection package
type HTTPFingerprintAnalyzer struct {
	HeaderPatterns map[string]*HeaderPattern `json:"header_patterns"`
	OrderPatterns  map[string][]string       `json:"order_patterns"`
	UserAgentDB    *UserAgentDatabase        `json:"user_agent_db"`
	HTTPVersions   []string                  `json:"http_versions"`
}

type BrowserFingerprintAnalyzer struct {
	UserAgentParser  *UserAgentParser  `json:"user_agent_parser"`
	FeatureExtractor *FeatureExtractor `json:"feature_extractor"`
	Classifier       Model             `json:"classifier"`
	Database         *BrowserDatabase  `json:"database"`
}

type UserAgentParser struct {
	Patterns   map[string]*UAPattern `json:"patterns"`
	Rules      []*ParsingRule        `json:"rules"`
	Cache      map[string]*ParsedUA  `json:"cache"`
	LastUpdate time.Time             `json:"last_update"`
}

type ParsingRule struct {
	Pattern  string            `json:"pattern"`
	Fields   map[string]string `json:"fields"`
	Priority int               `json:"priority"`
	Enabled  bool              `json:"enabled"`
}

type ParsedUA struct {
	Browser    string  `json:"browser"`
	Version    string  `json:"version"`
	OS         string  `json:"os"`
	Device     string  `json:"device"`
	Bot        bool    `json:"bot"`
	Confidence float64 `json:"confidence"`
}

type FeatureExtractor struct {
	Features      []string                        `json:"features"`
	Extractors    map[string]func(string) float64 `json:"-"`
	Weights       map[string]float64              `json:"weights"`
	Normalization bool                            `json:"normalization"`
}

type BrowserDatabase struct {
	Browsers   map[string]*BrowserInfo `json:"browsers"`
	Versions   map[string][]string     `json:"versions"`
	LastUpdate time.Time               `json:"last_update"`
	Version    string                  `json:"version"`
}

type BrowserInfo struct {
	Name       string   `json:"name"`
	Vendor     string   `json:"vendor"`
	Engine     string   `json:"engine"`
	Type       string   `json:"type"`
	Features   []string `json:"features"`
	Signatures []string `json:"signatures"`
}

type CanvasFingerprintAnalyzer struct {
	TestCases     []*CanvasTest   `json:"test_cases"`
	HashAlgorithm string          `json:"hash_algorithm"`
	Detector      *BotDetector    `json:"detector"`
	Database      *CanvasDatabase `json:"database"`
}

type CanvasTest struct {
	Name      string                 `json:"name"`
	Script    string                 `json:"script"`
	Expected  map[string]interface{} `json:"expected"`
	Tolerance float64                `json:"tolerance"`
}

type BotDetector struct {
	Rules     []*DetectionRule `json:"rules"`
	Threshold float64          `json:"threshold"`
	Algorithm string           `json:"algorithm"`
	Model     Model            `json:"model"`
}

type CanvasDatabase struct {
	Fingerprints map[string]*CanvasFingerprint `json:"fingerprints"`
	Clusters     map[string][]string           `json:"clusters"`
	Statistics   *FingerprintStats             `json:"statistics"`
	LastUpdate   time.Time                     `json:"last_update"`
}

type CanvasFingerprint struct {
	Hash      string    `json:"hash"`
	Data      string    `json:"data"`
	Browser   string    `json:"browser"`
	OS        string    `json:"os"`
	Device    string    `json:"device"`
	BotScore  float64   `json:"bot_score"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	Count     int       `json:"count"`
}

type FingerprintStats struct {
	TotalFingerprints int       `json:"total_fingerprints"`
	UniqueBrowsers    int       `json:"unique_browsers"`
	BotRatio          float64   `json:"bot_ratio"`
	EntropyScore      float64   `json:"entropy_score"`
	LastCalculated    time.Time `json:"last_calculated"`
}

type AudioFingerprintAnalyzer struct {
	Tests    []*AudioTest   `json:"tests"`
	Analyzer *AudioAnalyzer `json:"analyzer"`
	Database *AudioDatabase `json:"database"`
	Detector *BotDetector   `json:"detector"`
}

type AudioTest struct {
	Name      string         `json:"name"`
	Frequency float64        `json:"frequency"`
	Duration  time.Duration  `json:"duration"`
	Expected  *AudioResponse `json:"expected"`
}

type AudioResponse struct {
	Hash      string        `json:"hash"`
	Samples   []float64     `json:"samples"`
	Frequency float64       `json:"frequency"`
	Amplitude float64       `json:"amplitude"`
	Latency   time.Duration `json:"latency"`
}

type AudioAnalyzer struct {
	SampleRate int    `json:"sample_rate"`
	FFTSize    int    `json:"fft_size"`
	WindowType string `json:"window_type"`
	Algorithm  string `json:"algorithm"`
}

type AudioDatabase struct {
	Fingerprints map[string]*AudioFingerprint `json:"fingerprints"`
	Profiles     map[string]*AudioProfile     `json:"profiles"`
	LastUpdate   time.Time                    `json:"last_update"`
}

type AudioFingerprint struct {
	Hash      string    `json:"hash"`
	Spectrum  []float64 `json:"spectrum"`
	Browser   string    `json:"browser"`
	OS        string    `json:"os"`
	Device    string    `json:"device"`
	BotScore  float64   `json:"bot_score"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

type AudioProfile struct {
	Name       string            `json:"name"`
	Type       string            `json:"type"`
	Signatures []*AudioSignature `json:"signatures"`
	Threshold  float64           `json:"threshold"`
}

type AudioSignature struct {
	Pattern     []float64 `json:"pattern"`
	Tolerance   float64   `json:"tolerance"`
	Weight      float64   `json:"weight"`
	Description string    `json:"description"`
}

type WebGLFingerprintAnalyzer struct {
	Tests    []*WebGLTest   `json:"tests"`
	Renderer *WebGLRenderer `json:"renderer"`
	Database *WebGLDatabase `json:"database"`
	Detector *BotDetector   `json:"detector"`
}

type WebGLTest struct {
	Name     string         `json:"name"`
	Shader   string         `json:"shader"`
	Type     string         `json:"type"`
	Expected *WebGLResponse `json:"expected"`
}

type WebGLResponse struct {
	Renderer   string                 `json:"renderer"`
	Vendor     string                 `json:"vendor"`
	Version    string                 `json:"version"`
	Extensions []string               `json:"extensions"`
	Parameters map[string]interface{} `json:"parameters"`
	Hash       string                 `json:"hash"`
}

type WebGLRenderer struct {
	SupportedExtensions []string `json:"supported_extensions"`
	MaxTextureSize      int      `json:"max_texture_size"`
	MaxVertexAttribs    int      `json:"max_vertex_attribs"`
	ShadingLanguage     string   `json:"shading_language"`
}

type WebGLDatabase struct {
	Fingerprints map[string]*WebGLFingerprint `json:"fingerprints"`
	Devices      map[string]*DeviceProfile    `json:"devices"`
	LastUpdate   time.Time                    `json:"last_update"`
}

type WebGLFingerprint struct {
	Hash       string                 `json:"hash"`
	Renderer   string                 `json:"renderer"`
	Vendor     string                 `json:"vendor"`
	Extensions []string               `json:"extensions"`
	Parameters map[string]interface{} `json:"parameters"`
	BotScore   float64                `json:"bot_score"`
	FirstSeen  time.Time              `json:"first_seen"`
	LastSeen   time.Time              `json:"last_seen"`
}

type DeviceProfile struct {
	Name          string             `json:"name"`
	Type          string             `json:"type"`
	Vendor        string             `json:"vendor"`
	Signatures    []*DeviceSignature `json:"signatures"`
	BotLikelihood float64            `json:"bot_likelihood"`
}

type DeviceSignature struct {
	Property  string      `json:"property"`
	Value     interface{} `json:"value"`
	Weight    float64     `json:"weight"`
	Tolerance float64     `json:"tolerance"`
}

type FontFingerprintAnalyzer struct {
	FontList   []string      `json:"font_list"`
	TestMethod string        `json:"test_method"`
	Database   *FontDatabase `json:"database"`
	Detector   *BotDetector  `json:"detector"`
}

type FontDatabase struct {
	Fonts      map[string]*FontInfo    `json:"fonts"`
	Systems    map[string]*SystemFonts `json:"systems"`
	LastUpdate time.Time               `json:"last_update"`
}

type FontInfo struct {
	Name        string   `json:"name"`
	Family      string   `json:"family"`
	Type        string   `json:"type"`
	Systems     []string `json:"systems"`
	Commonality float64  `json:"commonality"`
}

type SystemFonts struct {
	OS            string   `json:"os"`
	Version       string   `json:"version"`
	DefaultFonts  []string `json:"default_fonts"`
	OptionalFonts []string `json:"optional_fonts"`
}

type TimingFingerprintAnalyzer struct {
	Tests    []*TimingTest   `json:"tests"`
	Analyzer *TimingAnalyzer `json:"analyzer"`
	Database *TimingDatabase `json:"database"`
	Detector *BotDetector    `json:"detector"`
}

type TimingTest struct {
	Name       string          `json:"name"`
	Operation  string          `json:"operation"`
	Iterations int             `json:"iterations"`
	Expected   *TimingResponse `json:"expected"`
}

type TimingResponse struct {
	Duration    time.Duration   `json:"duration"`
	Variance    time.Duration   `json:"variance"`
	Pattern     []time.Duration `json:"pattern"`
	Consistency float64         `json:"consistency"`
}

type TimingAnalyzer struct {
	Precision  time.Duration `json:"precision"`
	SampleSize int           `json:"sample_size"`
	Algorithm  string        `json:"algorithm"`
	Filters    []string      `json:"filters"`
}

type TimingDatabase struct {
	Profiles   map[string]*TimingProfile  `json:"profiles"`
	Baselines  map[string]*TimingBaseline `json:"baselines"`
	LastUpdate time.Time                  `json:"last_update"`
}

type TimingProfile struct {
	Browser  string                     `json:"browser"`
	OS       string                     `json:"os"`
	Device   string                     `json:"device"`
	Patterns map[string]*TimingResponse `json:"patterns"`
	BotScore float64                    `json:"bot_score"`
}

type TimingBaseline struct {
	Operation string        `json:"operation"`
	MinTime   time.Duration `json:"min_time"`
	MaxTime   time.Duration `json:"max_time"`
	AvgTime   time.Duration `json:"avg_time"`
	Variance  time.Duration `json:"variance"`
}

type EntropyCalculator struct {
	Algorithm  string   `json:"algorithm"`
	WindowSize int      `json:"window_size"`
	Threshold  float64  `json:"threshold"`
	Features   []string `json:"features"`
}

type MouseMovementTracker struct {
	SampleRate int               `json:"sample_rate"`
	Buffer     []*MouseMovement  `json:"buffer"`
	Analyzer   *MovementAnalyzer `json:"analyzer"`
	Detector   *BotDetector      `json:"detector"`
}

type MovementAnalyzer struct {
	Algorithm string   `json:"algorithm"`
	Features  []string `json:"features"`
	Model     Model    `json:"model"`
	Threshold float64  `json:"threshold"`
}

type KeyboardPatternTracker struct {
	Buffer   []*KeyboardEvent `json:"buffer"`
	Analyzer *TypingAnalyzer  `json:"analyzer"`
	Detector *BotDetector     `json:"detector"`
	Features *TypingFeatures  `json:"features"`
}

type TypingAnalyzer struct {
	Algorithm string   `json:"algorithm"`
	Model     Model    `json:"model"`
	Threshold float64  `json:"threshold"`
	Features  []string `json:"features"`
}

type TypingFeatures struct {
	DwellTimes  []time.Duration `json:"dwell_times"`
	FlightTimes []time.Duration `json:"flight_times"`
	Rhythm      *TypingRhythm   `json:"rhythm"`
	Patterns    map[string]int  `json:"patterns"`
}

type TypingRhythm struct {
	Tempo       float64         `json:"tempo"`
	Consistency float64         `json:"consistency"`
	Pauses      []time.Duration `json:"pauses"`
	Bursts      []int           `json:"bursts"`
}

// Additional protection types
type ScrollBehaviorTracker struct {
	Patterns  map[string]*ScrollPattern `json:"patterns"`
	Velocity  float64                   `json:"velocity"`
	Direction string                    `json:"direction"`
	Config    map[string]interface{}    `json:"config"`
}

type ScrollPattern struct {
	Direction    string    `json:"direction"`
	Speed        float64   `json:"speed"`
	Acceleration float64   `json:"acceleration"`
	Timestamp    time.Time `json:"timestamp"`
}

type ClickPatternAnalyzer struct {
	Patterns  []*ClickPattern        `json:"patterns"`
	Frequency float64                `json:"frequency"`
	Timing    []time.Duration        `json:"timing"`
	Config    map[string]interface{} `json:"config"`
}

type ClickPattern struct {
	X         int           `json:"x"`
	Y         int           `json:"y"`
	Button    int           `json:"button"`
	Timestamp time.Time     `json:"timestamp"`
	Duration  time.Duration `json:"duration"`
}

type NavigationAnalyzer struct {
	Paths     []*NavigationPath      `json:"paths"`
	Patterns  map[string]int         `json:"patterns"`
	Anomalies []string               `json:"anomalies"`
	Config    map[string]interface{} `json:"config"`
}

type NavigationPath struct {
	URL       string        `json:"url"`
	Method    string        `json:"method"`
	Timestamp time.Time     `json:"timestamp"`
	Duration  time.Duration `json:"duration"`
	Referer   string        `json:"referer"`
}

type InteractionAnalyzer struct {
	Events   []*InteractionEvent    `json:"events"`
	Patterns map[string]float64     `json:"patterns"`
	Score    float64                `json:"score"`
	Config   map[string]interface{} `json:"config"`
}

type InteractionEvent struct {
	Type      string                 `json:"type"`
	Target    string                 `json:"target"`
	Value     string                 `json:"value"`
	Timestamp time.Time              `json:"timestamp"`
	Metadata  map[string]interface{} `json:"metadata"`
}

type SessionAnalyzer struct {
	Sessions  map[string]*UserSession `json:"sessions"`
	Patterns  []*SessionPattern       `json:"patterns"`
	Anomalies []string                `json:"anomalies"`
	Config    map[string]interface{}  `json:"config"`
}

type SessionPattern struct {
	Duration     time.Duration `json:"duration"`
	RequestCount int           `json:"request_count"`
	UserAgent    string        `json:"user_agent"`
	IPs          []string      `json:"ips"`
	Score        float64       `json:"score"`
}

type AbnormalityDetector struct {
	Thresholds map[string]float64     `json:"thresholds"`
	Algorithms []string               `json:"algorithms"`
	Models     []*DetectionModel      `json:"models"`
	Config     map[string]interface{} `json:"config"`
}

type DetectionModel struct {
	Name        string                 `json:"name"`
	Type        string                 `json:"type"`
	Accuracy    float64                `json:"accuracy"`
	LastTrained time.Time              `json:"last_trained"`
	Config      map[string]interface{} `json:"config"`
}

type EnsembleClassifier struct {
	Models   []*ClassificationModel `json:"models"`
	Strategy string                 `json:"strategy"`
	Weights  []float64              `json:"weights"`
	Config   map[string]interface{} `json:"config"`
}

type ClassificationModel struct {
	Name     string                 `json:"name"`
	Type     string                 `json:"type"`
	Features []string               `json:"features"`
	Accuracy float64                `json:"accuracy"`
	Config   map[string]interface{} `json:"config"`
}

type NetworkLayer struct {
	Type       string                 `json:"type"`
	Size       int                    `json:"size"`
	Activation string                 `json:"activation"`
	Weights    [][]float64            `json:"weights"`
	Biases     []float64              `json:"biases"`
	Config     map[string]interface{} `json:"config"`
}

type DeepLearningModel struct {
	Architecture string                 `json:"architecture"`
	Layers       []*NetworkLayer        `json:"layers"`
	Optimizer    string                 `json:"optimizer"`
	LossFunction string                 `json:"loss_function"`
	Trained      bool                   `json:"trained"`
	Config       map[string]interface{} `json:"config"`
}

type DecisionTree struct {
	Root       *TreeNode              `json:"root"`
	MaxDepth   int                    `json:"max_depth"`
	MinSamples int                    `json:"min_samples"`
	Config     map[string]interface{} `json:"config"`
}

type TreeNode struct {
	Feature   string    `json:"feature"`
	Threshold float64   `json:"threshold"`
	Left      *TreeNode `json:"left"`
	Right     *TreeNode `json:"right"`
	Value     float64   `json:"value"`
	IsLeaf    bool      `json:"is_leaf"`
}

// Protection types
type FingerprintEngine struct {
	Collectors map[string]*DataCollector `json:"collectors"`
	Analyzers  []*FingerprintAnalyzer    `json:"analyzers"`
	Database   *FingerprintDatabase      `json:"database"`
	Config     map[string]interface{}    `json:"config"`
}

type ChallengeSystem struct {
	Types     map[string]*ChallengeType `json:"types"`
	Generator *ChallengeGenerator       `json:"generator"`
	Validator *ChallengeValidator       `json:"validator"`
	Store     *ChallengeStore           `json:"store"`
}

type DeviceIntelligence struct {
	Fingerprints map[string]*DeviceFingerprint `json:"fingerprints"`
	Classifier   *DeviceClassifier             `json:"classifier"`
	Database     *DeviceDatabase               `json:"database"`
	Updater      *DeviceUpdater                `json:"updater"`
}

type BiometricAnalyzer struct {
	Keystroke  *KeystrokeAnalyzer  `json:"keystroke"`
	Mouse      *MouseAnalyzer      `json:"mouse"`
	Touch      *TouchAnalyzer      `json:"touch"`
	Behavioral *BehavioralAnalyzer `json:"behavioral"`
}

type TemporalAnalyzer struct {
	Patterns []*TemporalPattern     `json:"patterns"`
	Windows  []*TimeWindow          `json:"windows"`
	Detector *TemporalDetector      `json:"detector"`
	Config   map[string]interface{} `json:"config"`
}

type BotKnowledgeGraph struct {
	Entities  map[string]*BotEntity `json:"entities"`
	Relations []*BotRelation        `json:"relations"`
	Rules     []*InferenceRule      `json:"rules"`
	Reasoner  *GraphReasoner        `json:"reasoner"`
}

type BotProtectionStats struct {
	TotalRequests  int64   `json:"total_requests"`
	BlockedBots    int64   `json:"blocked_bots"`
	ChallengesSent int64   `json:"challenges_sent"`
	FalsePositives int64   `json:"false_positives"`
	PerformanceMS  float64 `json:"performance_ms"`
}

// Missing support types
type AdaptiveModel struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"`
	Algorithm   string                 `json:"algorithm"`
	Parameters  map[string]interface{} `json:"parameters"`
	Performance *ModelPerformance      `json:"performance"`
}

type AdaptationRule struct {
	ID        string `json:"id"`
	Condition string `json:"condition"`
	Action    string `json:"action"`
	Priority  int    `json:"priority"`
	Active    bool   `json:"active"`
}

type PerformanceMonitor struct {
	Metrics    map[string]float64 `json:"metrics"`
	Thresholds map[string]float64 `json:"thresholds"`
	Alerts     []string           `json:"alerts"`
	History    []time.Time        `json:"history"`
}

type TransformerLayer struct {
	Type    string                 `json:"type"`
	Size    int                    `json:"size"`
	Heads   int                    `json:"heads"`
	Weights [][]float64            `json:"weights"`
	Config  map[string]interface{} `json:"config"`
}

type AttentionHead struct {
	ID        int         `json:"id"`
	Weights   [][]float64 `json:"weights"`
	Dimension int         `json:"dimension"`
	Active    bool        `json:"active"`
}

type ModelValidator struct {
	Tests      []string               `json:"tests"`
	Metrics    []string               `json:"metrics"`
	Thresholds map[string]float64     `json:"thresholds"`
	Results    map[string]interface{} `json:"results"`
}

type AdaptiveEngine struct {
	Models     []*AdaptiveModel      `json:"models"`
	Rules      []*AdaptationRule     `json:"rules"`
	Controller *AdaptationController `json:"controller"`
	Monitor    *PerformanceMonitor   `json:"monitor"`
}

type TransformerModel struct {
	Architecture string                 `json:"architecture"`
	Layers       []*TransformerLayer    `json:"layers"`
	Attention    []*AttentionHead       `json:"attention"`
	Config       map[string]interface{} `json:"config"`
}

type ModelUpdater struct {
	Schedule  string                 `json:"schedule"`
	Sources   []string               `json:"sources"`
	Validator *ModelValidator        `json:"validator"`
	Config    map[string]interface{} `json:"config"`
}

// Additional support types for protection
type DataCollector struct {
	Type   string                 `json:"type"`
	Source string                 `json:"source"`
	Active bool                   `json:"active"`
	Config map[string]interface{} `json:"config"`
}

type FingerprintAnalyzer struct {
	Algorithm string         `json:"algorithm"`
	Features  []string       `json:"features"`
	Model     *AnalysisModel `json:"model"`
	Accuracy  float64        `json:"accuracy"`
}

type FingerprintDatabase struct {
	Fingerprints map[string]*Fingerprint `json:"fingerprints"`
	Index        map[string][]string     `json:"index"`
	Size         int                     `json:"size"`
	Updated      time.Time               `json:"updated"`
}

type ChallengeGenerator struct {
	Types      []string               `json:"types"`
	Difficulty int                    `json:"difficulty"`
	Templates  map[string]string      `json:"templates"`
	Config     map[string]interface{} `json:"config"`
}

type ChallengeValidator struct {
	Validators map[string]*Validator  `json:"validators"`
	Timeout    time.Duration          `json:"timeout"`
	Retries    int                    `json:"retries"`
	Config     map[string]interface{} `json:"config"`
}

type ChallengeStore struct {
	Challenges map[string]*Challenge `json:"challenges"`
	TTL        time.Duration         `json:"ttl"`
	MaxSize    int                   `json:"max_size"`
	Cleanup    time.Duration         `json:"cleanup"`
}

type DeviceFingerprint struct {
	ID         string                 `json:"id"`
	Type       string                 `json:"type"`
	Features   map[string]interface{} `json:"features"`
	Confidence float64                `json:"confidence"`
	Created    time.Time              `json:"created"`
}

type DeviceClassifier struct {
	Model    *ClassificationModel `json:"model"`
	Features []string             `json:"features"`
	Classes  []string             `json:"classes"`
	Accuracy float64              `json:"accuracy"`
}

type DeviceDatabase struct {
	Devices    map[string]*Device  `json:"devices"`
	Categories map[string][]string `json:"categories"`
	Updated    time.Time           `json:"updated"`
	Version    string              `json:"version"`
}

type DeviceUpdater struct {
	Source     string        `json:"source"`
	Schedule   time.Duration `json:"schedule"`
	LastUpdate time.Time     `json:"last_update"`
	Active     bool          `json:"active"`
}

// Analyzer types
type KeystrokeAnalyzer struct {
	Patterns  map[string]*KeystrokePattern `json:"patterns"`
	Model     *BiometricModel              `json:"model"`
	Threshold float64                      `json:"threshold"`
	Active    bool                         `json:"active"`
}

type MouseAnalyzer struct {
	Patterns  map[string]*MousePattern `json:"patterns"`
	Model     *BiometricModel          `json:"model"`
	Threshold float64                  `json:"threshold"`
	Active    bool                     `json:"active"`
}

type TouchAnalyzer struct {
	Patterns  map[string]*TouchPattern `json:"patterns"`
	Model     *BiometricModel          `json:"model"`
	Threshold float64                  `json:"threshold"`
	Active    bool                     `json:"active"`
}

type BehaviorModel struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"`
	Algorithm   string                 `json:"algorithm"`
	Features    []string               `json:"features"`
	Parameters  map[string]interface{} `json:"parameters"`
	Performance *ModelPerformance      `json:"performance"`
	Trained     bool                   `json:"trained"`
	Created     time.Time              `json:"created"`
}

type BehavioralAnalyzer struct {
	Models    []*BehaviorModel       `json:"models"`
	Detectors []*BehaviorDetector    `json:"detectors"`
	Baselines []*BehaviorBaseline    `json:"baselines"`
	Config    map[string]interface{} `json:"config"`
}

type TemporalDetector struct {
	Windows   []*TimeWindow          `json:"windows"`
	Patterns  []*TemporalPattern     `json:"patterns"`
	Anomalies []*TemporalAnomaly     `json:"anomalies"`
	Config    map[string]interface{} `json:"config"`
}

type BotEntity struct {
	ID         string                 `json:"id"`
	Type       string                 `json:"type"`
	Properties map[string]interface{} `json:"properties"`
	Relations  []string               `json:"relations"`
}

type Fingerprint struct {
	ID         string                 `json:"id"`
	Hash       string                 `json:"hash"`
	Features   map[string]interface{} `json:"features"`
	Confidence float64                `json:"confidence"`
	Created    time.Time              `json:"created"`
}

type Validator struct {
	Type   string                 `json:"type"`
	Rules  []string               `json:"rules"`
	Config map[string]interface{} `json:"config"`
	Active bool                   `json:"active"`
}

type Challenge struct {
	ID         string    `json:"id"`
	Type       string    `json:"type"`
	Content    string    `json:"content"`
	Solution   string    `json:"solution"`
	Difficulty int       `json:"difficulty"`
	Created    time.Time `json:"created"`
	Expires    time.Time `json:"expires"`
}

type Device struct {
	ID       string                 `json:"id"`
	Type     string                 `json:"type"`
	Name     string                 `json:"name"`
	Category string                 `json:"category"`
	Features map[string]interface{} `json:"features"`
}

// Final missing support types
type BotRelation struct {
	ID         string  `json:"id"`
	Source     string  `json:"source"`
	Target     string  `json:"target"`
	Type       string  `json:"type"`
	Weight     float64 `json:"weight"`
	Confidence float64 `json:"confidence"`
}

type KeystrokePattern struct {
	Sequence   []string        `json:"sequence"`
	Timing     []time.Duration `json:"timing"`
	Pressure   []float64       `json:"pressure"`
	DwellTime  time.Duration   `json:"dwell_time"`
	FlightTime time.Duration   `json:"flight_time"`
}

type BiometricModel struct {
	Algorithm string    `json:"algorithm"`
	Features  []string  `json:"features"`
	Weights   []float64 `json:"weights"`
	Threshold float64   `json:"threshold"`
	Accuracy  float64   `json:"accuracy"`
	Trained   bool      `json:"trained"`
}

type MousePattern struct {
	Path         []MousePoint  `json:"path"`
	Velocity     []float64     `json:"velocity"`
	Acceleration []float64     `json:"acceleration"`
	Clicks       []ClickPoint  `json:"clicks"`
	Duration     time.Duration `json:"duration"`
}

type MousePoint struct {
	X         int       `json:"x"`
	Y         int       `json:"y"`
	Timestamp time.Time `json:"timestamp"`
	Pressure  float64   `json:"pressure"`
}

type ClickPoint struct {
	X         int           `json:"x"`
	Y         int           `json:"y"`
	Button    int           `json:"button"`
	Timestamp time.Time     `json:"timestamp"`
	Duration  time.Duration `json:"duration"`
}

type TouchPattern struct {
	Points   []TouchPoint   `json:"points"`
	Gestures []TouchGesture `json:"gestures"`
	Pressure []float64      `json:"pressure"`
	Area     []float64      `json:"area"`
	Duration time.Duration  `json:"duration"`
}

type TouchPoint struct {
	X         float64   `json:"x"`
	Y         float64   `json:"y"`
	Timestamp time.Time `json:"timestamp"`
	Pressure  float64   `json:"pressure"`
	Area      float64   `json:"area"`
}

type TouchGesture struct {
	Type      string        `json:"type"`
	Direction string        `json:"direction"`
	Distance  float64       `json:"distance"`
	Velocity  float64       `json:"velocity"`
	Duration  time.Duration `json:"duration"`
}

type BehaviorDetector struct {
	Algorithm string          `json:"algorithm"`
	Model     *BiometricModel `json:"model"`
	Threshold float64         `json:"threshold"`
	Features  []string        `json:"features"`
	Active    bool            `json:"active"`
}

type BehaviorBaseline struct {
	UserID   string                 `json:"user_id"`
	Patterns map[string]interface{} `json:"patterns"`
	Metrics  map[string]float64     `json:"metrics"`
	Created  time.Time              `json:"created"`
	Updated  time.Time              `json:"updated"`
}

type TemporalAnomaly struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"`
	Timestamp   time.Time              `json:"timestamp"`
	Severity    float64                `json:"severity"`
	Description string                 `json:"description"`
	Context     map[string]interface{} `json:"context"`
}

// Additional missing types
type InferenceRule struct {
	ID         string  `json:"id"`
	Name       string  `json:"name"`
	Condition  string  `json:"condition"`
	Conclusion string  `json:"conclusion"`
	Confidence float64 `json:"confidence"`
	Priority   int     `json:"priority"`
	Active     bool    `json:"active"`
}

type GraphReasoner struct {
	Engine string                 `json:"engine"`
	Rules  []*InferenceRule       `json:"rules"`
	Facts  map[string]interface{} `json:"facts"`
	Memory map[string]interface{} `json:"memory"`
	Config map[string]interface{} `json:"config"`
}

// Dashboard and analytics types
type RealTimeEngine struct {
	ID         string                 `json:"id"`
	Type       string                 `json:"type"`
	Streams    []string               `json:"streams"`
	Processors []string               `json:"processors"`
	Config     map[string]interface{} `json:"config"`
	Status     string                 `json:"status"`
	Created    time.Time              `json:"created"`
}

type AnalyticsEngine struct {
	ID        string                 `json:"id"`
	Type      string                 `json:"type"`
	Analyzers []string               `json:"analyzers"`
	Models    []string               `json:"models"`
	Config    map[string]interface{} `json:"config"`
	Status    string                 `json:"status"`
	Created   time.Time              `json:"created"`
}

type AlertManager struct {
	ID      string                 `json:"id"`
	Type    string                 `json:"type"`
	Alerts  []string               `json:"alerts"`
	Rules   []string               `json:"rules"`
	Config  map[string]interface{} `json:"config"`
	Status  string                 `json:"status"`
	Created time.Time              `json:"created"`
}

type IncidentManager struct {
	ID        string                 `json:"id"`
	Type      string                 `json:"type"`
	Incidents []string               `json:"incidents"`
	Workflows []string               `json:"workflows"`
	Config    map[string]interface{} `json:"config"`
	Status    string                 `json:"status"`
	Created   time.Time              `json:"created"`
}

type ThreatIntelligencePanel struct {
	ID      string                 `json:"id"`
	Type    string                 `json:"type"`
	Feeds   []string               `json:"feeds"`
	Sources []string               `json:"sources"`
	Config  map[string]interface{} `json:"config"`
	Status  string                 `json:"status"`
	Created time.Time              `json:"created"`
}

type ComplianceMonitor struct {
	ID         string                 `json:"id"`
	Type       string                 `json:"type"`
	Frameworks []string               `json:"frameworks"`
	Controls   []string               `json:"controls"`
	Config     map[string]interface{} `json:"config"`
	Status     string                 `json:"status"`
	Created    time.Time              `json:"created"`
}

type CollaborationHub struct {
	ID      string                 `json:"id"`
	Type    string                 `json:"type"`
	Users   []string               `json:"users"`
	Teams   []string               `json:"teams"`
	Config  map[string]interface{} `json:"config"`
	Status  string                 `json:"status"`
	Created time.Time              `json:"created"`
}

type SecurityMetrics struct {
	ID      string                 `json:"id"`
	Type    string                 `json:"type"`
	Metrics []string               `json:"metrics"`
	KPIs    []string               `json:"kpis"`
	Config  map[string]interface{} `json:"config"`
	Status  string                 `json:"status"`
	Created time.Time              `json:"created"`
}

type KPICalculator struct {
	ID       string                 `json:"id"`
	Type     string                 `json:"type"`
	KPIs     []string               `json:"kpis"`
	Formulas []string               `json:"formulas"`
	Config   map[string]interface{} `json:"config"`
	Status   string                 `json:"status"`
	Created  time.Time              `json:"created"`
}

type MapRenderer struct {
	ID      string                 `json:"id"`
	Type    string                 `json:"type"`
	Maps    []string               `json:"maps"`
	Layers  []string               `json:"layers"`
	Config  map[string]interface{} `json:"config"`
	Status  string                 `json:"status"`
	Created time.Time              `json:"created"`
}

// Missing dashboard rendering types
type GraphRenderer struct {
	Enabled         bool   `yaml:"enabled"`
	Type            string `yaml:"type"`
	Layout          string `yaml:"layout"`
	InteractionMode string `yaml:"interaction_mode"`
}

type HeatmapRenderer struct {
	Enabled     bool   `yaml:"enabled"`
	ColorScheme string `yaml:"color_scheme"`
	Resolution  string `yaml:"resolution"`
	Aggregation string `yaml:"aggregation"`
}

type TimelineRenderer struct {
	Enabled    bool     `yaml:"enabled"`
	ZoomLevel  string   `yaml:"zoom_level"`
	TimeRange  string   `yaml:"time_range"`
	EventTypes []string `yaml:"event_types"`
}

type NetworkRenderer struct {
	Enabled   bool   `yaml:"enabled"`
	Layout    string `yaml:"layout"`
	NodeStyle string `yaml:"node_style"`
	EdgeStyle string `yaml:"edge_style"`
}

type FlowRenderer struct {
	Enabled        bool     `yaml:"enabled"`
	Direction      string   `yaml:"direction"`
	AnimationSpeed string   `yaml:"animation_speed"`
	FlowTypes      []string `yaml:"flow_types"`
}

type DashboardRenderer struct {
	Enabled     bool          `yaml:"enabled"`
	Theme       string        `yaml:"theme"`
	Layout      string        `yaml:"layout"`
	RefreshRate time.Duration `yaml:"refresh_rate"`
}

type ReportRenderer struct {
	Enabled    bool   `yaml:"enabled"`
	Format     string `yaml:"format"`
	Template   string `yaml:"template"`
	OutputPath string `yaml:"output_path"`
}

type InteractivityEngine struct {
	Enabled       bool              `yaml:"enabled"`
	Features      []string          `yaml:"features"`
	EventHandlers map[string]string `yaml:"event_handlers"`
	ResponseTime  time.Duration     `yaml:"response_time"`
}

type AnimationEngine struct {
	Enabled     bool     `yaml:"enabled"`
	FrameRate   int      `yaml:"frame_rate"`
	Transitions []string `yaml:"transitions"`
	Performance string   `yaml:"performance"`
}

type ResponsiveEngine struct {
	Enabled         bool           `yaml:"enabled"`
	Breakpoints     map[string]int `yaml:"breakpoints"`
	AdaptiveMode    string         `yaml:"adaptive_mode"`
	MobileOptimized bool           `yaml:"mobile_optimized"`
}

// Missing alert management types
type AlertProcessor struct {
	Enabled         bool                   `yaml:"enabled"`
	ProcessingRules []string               `yaml:"processing_rules"`
	FilterCriteria  map[string]interface{} `yaml:"filter_criteria"`
	OutputChannels  []string               `yaml:"output_channels"`
}

type AlertPrioritizer struct {
	Enabled         bool               `yaml:"enabled"`
	PriorityRules   []string           `yaml:"priority_rules"`
	SeverityMapping map[string]int     `yaml:"severity_mapping"`
	BusinessImpact  map[string]float64 `yaml:"business_impact"`
}

type AlertCorrelator struct {
	Enabled             bool          `yaml:"enabled"`
	CorrelationRules    []string      `yaml:"correlation_rules"`
	TimeWindow          time.Duration `yaml:"time_window"`
	SimilarityThreshold float64       `yaml:"similarity_threshold"`
}

type AlertDeduplicator struct {
	Enabled        bool          `yaml:"enabled"`
	DedupeWindow   time.Duration `yaml:"dedupe_window"`
	MatchingFields []string      `yaml:"matching_fields"`
	HashAlgorithm  string        `yaml:"hash_algorithm"`
}

type EscalationEngine struct {
	Enabled         bool                     `yaml:"enabled"`
	EscalationRules []string                 `yaml:"escalation_rules"`
	TimeThresholds  map[string]time.Duration `yaml:"time_thresholds"`
	NotifyChain     []string                 `yaml:"notify_chain"`
}

type NotificationEngine struct {
	Enabled      bool              `yaml:"enabled"`
	Channels     []string          `yaml:"channels"`
	Templates    map[string]string `yaml:"templates"`
	RateLimiting bool              `yaml:"rate_limiting"`
}

type AlertAcknowledger struct {
	Enabled         bool          `yaml:"enabled"`
	AutoAck         bool          `yaml:"auto_ack"`
	AckTimeout      time.Duration `yaml:"ack_timeout"`
	RequireComments bool          `yaml:"require_comments"`
}

type AlertResolver struct {
	Enabled         bool     `yaml:"enabled"`
	AutoResolve     bool     `yaml:"auto_resolve"`
	ResolutionRules []string `yaml:"resolution_rules"`
	FollowUpActions []string `yaml:"followup_actions"`
}

type FalsePositiveDetector struct {
	Enabled             bool    `yaml:"enabled"`
	MLModel             string  `yaml:"ml_model"`
	ConfidenceThreshold float64 `yaml:"confidence_threshold"`
	LearningMode        string  `yaml:"learning_mode"`
}

type AlertEnrichment struct {
	Enabled         bool          `yaml:"enabled"`
	DataSources     []string      `yaml:"data_sources"`
	EnrichmentRules []string      `yaml:"enrichment_rules"`
	CacheTimeout    time.Duration `yaml:"cache_timeout"`
}
