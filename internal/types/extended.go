package types

import (
	"time"
)

// Time series data types
type TimeSeriesPoint struct {
	Timestamp time.Time `json:"timestamp"`
	Value     float64   `json:"value"`
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
	Name        string                 `json:"name"`
	Type        string                 `json:"type"`
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
	Method      string                 `json:"method"`
	Pooling     string                 `json:"pooling"`
	Dimensions  int                    `json:"dimensions"`
	Config      map[string]interface{} `json:"config"`
}

type ThreatCorrelator struct {
	Rules       []*CorrelationRule     `json:"rules"`
	Threshold   float64                `json:"threshold"`
	TimeWindow  time.Duration          `json:"time_window"`
	Config      map[string]interface{} `json:"config"`
}

type CorrelationRule struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Condition   string                 `json:"condition"`
	Score       float64                `json:"score"`
	Enabled     bool                   `json:"enabled"`
}

type ThreatCache struct {
	Entries     map[string]*ThreatEntry `json:"entries"`
	MaxEntries  int                     `json:"max_entries"`
	TTL         time.Duration           `json:"ttl"`
	HitRate     float64                 `json:"hit_rate"`
}

type ThreatEntry struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"`
	Value       string                 `json:"value"`
	Score       float64                `json:"score"`
	Source      string                 `json:"source"`
	Timestamp   time.Time              `json:"timestamp"`
	Metadata    map[string]interface{} `json:"metadata"`
}

type ReputationEngine struct {
	Sources     []string               `json:"sources"`
	Weights     map[string]float64     `json:"weights"`
	Threshold   float64                `json:"threshold"`
	Config      map[string]interface{} `json:"config"`
}

type IOCMatcher struct {
	Patterns    map[string]*IOCPattern `json:"patterns"`
	Threshold   float64                `json:"threshold"`
	Config      map[string]interface{} `json:"config"`
}

type IOCPattern struct {
	Type        string    `json:"type"`
	Pattern     string    `json:"pattern"`
	Confidence  float64   `json:"confidence"`
	Source      string    `json:"source"`
	CreatedAt   time.Time `json:"created_at"`
}

type DifferentialPrivacy struct {
	Epsilon     float64                `json:"epsilon"`
	Delta       float64                `json:"delta"`
	Sensitivity float64                `json:"sensitivity"`
	Mechanism   string                 `json:"mechanism"`
	Config      map[string]interface{} `json:"config"`
}

type HomomorphicEncryption struct {
	Scheme      string                 `json:"scheme"`
	KeySize     int                    `json:"key_size"`
	PublicKey   string                 `json:"public_key"`
	PrivateKey  string                 `json:"private_key"`
	Config      map[string]interface{} `json:"config"`
}

type SecureMultiPartyComputation struct {
	Protocol    string                 `json:"protocol"`
	Parties     []string               `json:"parties"`
	Threshold   int                    `json:"threshold"`
	Config      map[string]interface{} `json:"config"`
}

type NoiseGenerator struct {
	Type        string                 `json:"type"`
	Parameters  map[string]float64     `json:"parameters"`
	Seed        int64                  `json:"seed"`
	Config      map[string]interface{} `json:"config"`
}

// Missing types for Protection package
type HTTPFingerprintAnalyzer struct {
	HeaderPatterns map[string]*HeaderPattern `json:"header_patterns"`
	OrderPatterns  map[string][]string       `json:"order_patterns"`
	UserAgentDB    *UserAgentDatabase        `json:"user_agent_db"`
	HTTPVersions   []string                  `json:"http_versions"`
}

type BrowserFingerprintAnalyzer struct {
	UserAgentParser  *UserAgentParser       `json:"user_agent_parser"`
	FeatureExtractor *FeatureExtractor      `json:"feature_extractor"`
	Classifier       Model                  `json:"classifier"`
	Database         *BrowserDatabase       `json:"database"`
}

type UserAgentParser struct {
	Patterns    map[string]*UAPattern      `json:"patterns"`
	Rules       []*ParsingRule             `json:"rules"`
	Cache       map[string]*ParsedUA       `json:"cache"`
	LastUpdate  time.Time                  `json:"last_update"`
}

type ParsingRule struct {
	Pattern     string                     `json:"pattern"`
	Fields      map[string]string          `json:"fields"`
	Priority    int                        `json:"priority"`
	Enabled     bool                       `json:"enabled"`
}

type ParsedUA struct {
	Browser     string                     `json:"browser"`
	Version     string                     `json:"version"`
	OS          string                     `json:"os"`
	Device      string                     `json:"device"`
	Bot         bool                       `json:"bot"`
	Confidence  float64                    `json:"confidence"`
}

type FeatureExtractor struct {
	Features    []string                   `json:"features"`
	Extractors  map[string]func(string) float64 `json:"-"`
	Weights     map[string]float64         `json:"weights"`
	Normalization bool                     `json:"normalization"`
}

type BrowserDatabase struct {
	Browsers    map[string]*BrowserInfo    `json:"browsers"`
	Versions    map[string][]string        `json:"versions"`
	LastUpdate  time.Time                  `json:"last_update"`
	Version     string                     `json:"version"`
}

type BrowserInfo struct {
	Name        string                     `json:"name"`
	Vendor      string                     `json:"vendor"`
	Engine      string                     `json:"engine"`
	Type        string                     `json:"type"`
	Features    []string                   `json:"features"`
	Signatures  []string                   `json:"signatures"`
}

type CanvasFingerprintAnalyzer struct {
	TestCases   []*CanvasTest              `json:"test_cases"`
	HashAlgorithm string                   `json:"hash_algorithm"`
	Detector    *BotDetector               `json:"detector"`
	Database    *CanvasDatabase            `json:"database"`
}

type CanvasTest struct {
	Name        string                     `json:"name"`
	Script      string                     `json:"script"`
	Expected    map[string]interface{}     `json:"expected"`
	Tolerance   float64                    `json:"tolerance"`
}

type BotDetector struct {
	Rules       []*DetectionRule           `json:"rules"`
	Threshold   float64                    `json:"threshold"`
	Algorithm   string                     `json:"algorithm"`
	Model       Model                      `json:"model"`
}

type DetectionRule struct {
	Name        string                     `json:"name"`
	Condition   string                     `json:"condition"`
	Weight      float64                    `json:"weight"`
	Enabled     bool                       `json:"enabled"`
	Description string                     `json:"description"`
}

type CanvasDatabase struct {
	Fingerprints map[string]*CanvasFingerprint `json:"fingerprints"`
	Clusters    map[string][]string            `json:"clusters"`
	Statistics  *FingerprintStats              `json:"statistics"`
	LastUpdate  time.Time                      `json:"last_update"`
}

type CanvasFingerprint struct {
	Hash        string                         `json:"hash"`
	Data        string                         `json:"data"`
	Browser     string                         `json:"browser"`
	OS          string                         `json:"os"`
	Device      string                         `json:"device"`
	BotScore    float64                        `json:"bot_score"`
	FirstSeen   time.Time                      `json:"first_seen"`
	LastSeen    time.Time                      `json:"last_seen"`
	Count       int                            `json:"count"`
}

type FingerprintStats struct {
	TotalFingerprints int                        `json:"total_fingerprints"`
	UniqueBrowsers    int                        `json:"unique_browsers"`
	BotRatio          float64                    `json:"bot_ratio"`
	EntropyScore      float64                    `json:"entropy_score"`
	LastCalculated    time.Time                  `json:"last_calculated"`
}

type AudioFingerprintAnalyzer struct {
	Tests       []*AudioTest               `json:"tests"`
	Analyzer    *AudioAnalyzer             `json:"analyzer"`
	Database    *AudioDatabase             `json:"database"`
	Detector    *BotDetector               `json:"detector"`
}

type AudioTest struct {
	Name        string                     `json:"name"`
	Frequency   float64                    `json:"frequency"`
	Duration    time.Duration              `json:"duration"`
	Expected    *AudioResponse             `json:"expected"`
}

type AudioResponse struct {
	Hash        string                     `json:"hash"`
	Samples     []float64                  `json:"samples"`
	Frequency   float64                    `json:"frequency"`
	Amplitude   float64                    `json:"amplitude"`
	Latency     time.Duration              `json:"latency"`
}

type AudioAnalyzer struct {
	SampleRate  int                        `json:"sample_rate"`
	FFTSize     int                        `json:"fft_size"`
	WindowType  string                     `json:"window_type"`
	Algorithm   string                     `json:"algorithm"`
}

type AudioDatabase struct {
	Fingerprints map[string]*AudioFingerprint `json:"fingerprints"`
	Profiles    map[string]*AudioProfile      `json:"profiles"`
	LastUpdate  time.Time                     `json:"last_update"`
}

type AudioFingerprint struct {
	Hash        string                         `json:"hash"`
	Spectrum    []float64                      `json:"spectrum"`
	Browser     string                         `json:"browser"`
	OS          string                         `json:"os"`
	Device      string                         `json:"device"`
	BotScore    float64                        `json:"bot_score"`
	FirstSeen   time.Time                      `json:"first_seen"`
	LastSeen    time.Time                      `json:"last_seen"`
}

type AudioProfile struct {
	Name        string                         `json:"name"`
	Type        string                         `json:"type"`
	Signatures  []*AudioSignature              `json:"signatures"`
	Threshold   float64                        `json:"threshold"`
}

type AudioSignature struct {
	Pattern     []float64                      `json:"pattern"`
	Tolerance   float64                        `json:"tolerance"`
	Weight      float64                        `json:"weight"`
	Description string                         `json:"description"`
}

type WebGLFingerprintAnalyzer struct {
	Tests       []*WebGLTest               `json:"tests"`
	Renderer    *WebGLRenderer             `json:"renderer"`
	Database    *WebGLDatabase             `json:"database"`
	Detector    *BotDetector               `json:"detector"`
}

type WebGLTest struct {
	Name        string                     `json:"name"`
	Shader      string                     `json:"shader"`
	Type        string                     `json:"type"`
	Expected    *WebGLResponse             `json:"expected"`
}

type WebGLResponse struct {
	Renderer    string                     `json:"renderer"`
	Vendor      string                     `json:"vendor"`
	Version     string                     `json:"version"`
	Extensions  []string                   `json:"extensions"`
	Parameters  map[string]interface{}     `json:"parameters"`
	Hash        string                     `json:"hash"`
}

type WebGLRenderer struct {
	SupportedExtensions []string           `json:"supported_extensions"`
	MaxTextureSize      int                `json:"max_texture_size"`
	MaxVertexAttribs    int                `json:"max_vertex_attribs"`
	ShadingLanguage     string             `json:"shading_language"`
}

type WebGLDatabase struct {
	Fingerprints map[string]*WebGLFingerprint `json:"fingerprints"`
	Devices     map[string]*DeviceProfile     `json:"devices"`
	LastUpdate  time.Time                     `json:"last_update"`
}

type WebGLFingerprint struct {
	Hash        string                        `json:"hash"`
	Renderer    string                        `json:"renderer"`
	Vendor      string                        `json:"vendor"`
	Extensions  []string                      `json:"extensions"`
	Parameters  map[string]interface{}        `json:"parameters"`
	BotScore    float64                       `json:"bot_score"`
	FirstSeen   time.Time                     `json:"first_seen"`
	LastSeen    time.Time                     `json:"last_seen"`
}

type DeviceProfile struct {
	Name        string                        `json:"name"`
	Type        string                        `json:"type"`
	Vendor      string                        `json:"vendor"`
	Signatures  []*DeviceSignature            `json:"signatures"`
	BotLikelihood float64                     `json:"bot_likelihood"`
}

type DeviceSignature struct {
	Property    string                        `json:"property"`
	Value       interface{}                   `json:"value"`
	Weight      float64                       `json:"weight"`
	Tolerance   float64                       `json:"tolerance"`
}

type FontFingerprintAnalyzer struct {
	FontList    []string                      `json:"font_list"`
	TestMethod  string                        `json:"test_method"`
	Database    *FontDatabase                 `json:"database"`
	Detector    *BotDetector                  `json:"detector"`
}

type FontDatabase struct {
	Fonts       map[string]*FontInfo          `json:"fonts"`
	Systems     map[string]*SystemFonts       `json:"systems"`
	LastUpdate  time.Time                     `json:"last_update"`
}

type FontInfo struct {
	Name        string                        `json:"name"`
	Family      string                        `json:"family"`
	Type        string                        `json:"type"`
	Systems     []string                      `json:"systems"`
	Commonality float64                       `json:"commonality"`
}

type SystemFonts struct {
	OS          string                        `json:"os"`
	Version     string                        `json:"version"`
	DefaultFonts []string                     `json:"default_fonts"`
	OptionalFonts []string                    `json:"optional_fonts"`
}

type TimingFingerprintAnalyzer struct {
	Tests       []*TimingTest                 `json:"tests"`
	Analyzer    *TimingAnalyzer               `json:"analyzer"`
	Database    *TimingDatabase               `json:"database"`
	Detector    *BotDetector                  `json:"detector"`
}

type TimingTest struct {
	Name        string                        `json:"name"`
	Operation   string                        `json:"operation"`
	Iterations  int                           `json:"iterations"`
	Expected    *TimingResponse               `json:"expected"`
}

type TimingResponse struct {
	Duration    time.Duration                 `json:"duration"`
	Variance    time.Duration                 `json:"variance"`
	Pattern     []time.Duration               `json:"pattern"`
	Consistency float64                       `json:"consistency"`
}

type TimingAnalyzer struct {
	Precision   time.Duration                 `json:"precision"`
	SampleSize  int                           `json:"sample_size"`
	Algorithm   string                        `json:"algorithm"`
	Filters     []string                      `json:"filters"`
}

type TimingDatabase struct {
	Profiles    map[string]*TimingProfile     `json:"profiles"`
	Baselines   map[string]*TimingBaseline    `json:"baselines"`
	LastUpdate  time.Time                     `json:"last_update"`
}

type TimingProfile struct {
	Browser     string                        `json:"browser"`
	OS          string                        `json:"os"`
	Device      string                        `json:"device"`
	Patterns    map[string]*TimingResponse    `json:"patterns"`
	BotScore    float64                       `json:"bot_score"`
}

type TimingBaseline struct {
	Operation   string                        `json:"operation"`
	MinTime     time.Duration                 `json:"min_time"`
	MaxTime     time.Duration                 `json:"max_time"`
	AvgTime     time.Duration                 `json:"avg_time"`
	Variance    time.Duration                 `json:"variance"`
}

type EntropyCalculator struct {
	Algorithm   string                        `json:"algorithm"`
	WindowSize  int                           `json:"window_size"`
	Threshold   float64                       `json:"threshold"`
	Features    []string                      `json:"features"`
}

type MouseMovementTracker struct {
	SampleRate  int                           `json:"sample_rate"`
	Buffer      []*MouseMovement              `json:"buffer"`
	Analyzer    *MovementAnalyzer             `json:"analyzer"`
	Detector    *BotDetector                  `json:"detector"`
}

type MovementAnalyzer struct {
	Algorithm   string                        `json:"algorithm"`
	Features    []string                      `json:"features"`
	Model       Model                         `json:"model"`
	Threshold   float64                       `json:"threshold"`
}

type KeyboardPatternTracker struct {
	Buffer      []*KeyboardEvent              `json:"buffer"`
	Analyzer    *TypingAnalyzer               `json:"analyzer"`
	Detector    *BotDetector                  `json:"detector"`
	Features    *TypingFeatures               `json:"features"`
}

type TypingAnalyzer struct {
	Algorithm   string                        `json:"algorithm"`
	Model       Model                         `json:"model"`
	Threshold   float64                       `json:"threshold"`
	Features    []string                      `json:"features"`
}

type TypingFeatures struct {
	DwellTimes  []time.Duration               `json:"dwell_times"`
	FlightTimes []time.Duration               `json:"flight_times"`
	Rhythm      *TypingRhythm                 `json:"rhythm"`
	Patterns    map[string]int                `json:"patterns"`
}

type TypingRhythm struct {
	Tempo       float64                       `json:"tempo"`
	Consistency float64                       `json:"consistency"`
	Pauses      []time.Duration               `json:"pauses"`
	Bursts      []int                         `json:"bursts"`
}
