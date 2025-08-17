package types

import (
	"time"
)

// Hunting specific types
type HuntTool struct {
	ID           string                 `json:"id"`
	Name         string                 `json:"name"`
	Type         string                 `json:"type"`
	Version      string                 `json:"version"`
	Description  string                 `json:"description"`
	Category     string                 `json:"category"`
	Capabilities []string               `json:"capabilities"`
	Parameters   map[string]interface{} `json:"parameters"`
	Config       map[string]interface{} `json:"config"`
	Status       string                 `json:"status"`
	LastUsed     time.Time              `json:"last_used"`
	Performance  *ToolPerformance       `json:"performance"`
}

type ToolPerformance struct {
	AverageRuntime time.Duration `json:"average_runtime"`
	SuccessRate    float64       `json:"success_rate"`
	ErrorRate      float64       `json:"error_rate"`
	UsageCount     int64         `json:"usage_count"`
	LastBenchmark  time.Time     `json:"last_benchmark"`
}

type IndicatorType struct {
	Name        string   `json:"name"`
	Category    string   `json:"category"`
	DataType    string   `json:"data_type"`
	Validation  string   `json:"validation"`
	Examples    []string `json:"examples"`
	Description string   `json:"description"`
}

type PlaybookStep struct {
	ID           string                 `json:"id"`
	Name         string                 `json:"name"`
	Description  string                 `json:"description"`
	Type         string                 `json:"type"`
	Tool         string                 `json:"tool"`
	Parameters   map[string]interface{} `json:"parameters"`
	Conditions   []string               `json:"conditions"`
	Dependencies []string               `json:"dependencies"`
	Timeout      time.Duration          `json:"timeout"`
	Retries      int                    `json:"retries"`
	OnSuccess    string                 `json:"on_success"`
	OnFailure    string                 `json:"on_failure"`
}

type HuntingPlaybook struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Category    string                 `json:"category"`
	Author      string                 `json:"author"`
	Version     string                 `json:"version"`
	Tags        []string               `json:"tags"`
	Steps       []*PlaybookStep        `json:"steps"`
	Variables   map[string]interface{} `json:"variables"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
}

type HuntingQuery struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Query       string                 `json:"query"`
	Language    string                 `json:"language"`
	DataSources []string               `json:"data_sources"`
	Parameters  map[string]interface{} `json:"parameters"`
	Tags        []string               `json:"tags"`
	Author      string                 `json:"author"`
	CreatedAt   time.Time              `json:"created_at"`
}

type HuntingResult struct {
	ID            string                   `json:"id"`
	QueryID       string                   `json:"query_id"`
	SessionID     string                   `json:"session_id"`
	Status        string                   `json:"status"`
	Results       []map[string]interface{} `json:"results"`
	Count         int                      `json:"count"`
	ExecutionTime time.Duration            `json:"execution_time"`
	Error         string                   `json:"error"`
	StartedAt     time.Time                `json:"started_at"`
	CompletedAt   time.Time                `json:"completed_at"`
}

type HuntingSession struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Description string     `json:"description"`
	Hypothesis  string     `json:"hypothesis"`
	Status      string     `json:"status"`
	Hunter      string     `json:"hunter"`
	Queries     []string   `json:"queries"`
	Findings    []*Finding `json:"findings"`
	TimeRange   *TimeRange `json:"time_range"`
	Tags        []string   `json:"tags"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

type Finding struct {
	ID          string                   `json:"id"`
	Type        string                   `json:"type"`
	Title       string                   `json:"title"`
	Description string                   `json:"description"`
	Severity    string                   `json:"severity"`
	Confidence  float64                  `json:"confidence"`
	Evidence    []map[string]interface{} `json:"evidence"`
	IOCs        []*IOC                   `json:"iocs"`
	TTPs        []*TTP                   `json:"ttps"`
	Metadata    map[string]interface{}   `json:"metadata"`
	CreatedAt   time.Time                `json:"created_at"`
}

// Protection specific types
type TLSFingerprintAnalyzer struct {
	SupportedVersions []string               `json:"supported_versions"`
	CipherSuites      map[string][]string    `json:"cipher_suites"`
	Extensions        map[string][]string    `json:"extensions"`
	Patterns          map[string]*TLSPattern `json:"patterns"`
	Database          *FingerprintDatabase   `json:"database"`
}

type TLSPattern struct {
	Name       string   `json:"name"`
	Version    string   `json:"version"`
	Ciphers    []string `json:"ciphers"`
	Extensions []string `json:"extensions"`
	Curve      string   `json:"curve"`
	Signature  string   `json:"signature"`
	Confidence float64  `json:"confidence"`
}

type ClientFingerprint struct {
	JA3         string   `json:"ja3"`
	JA3S        string   `json:"ja3s"`
	UserAgent   string   `json:"user_agent"`
	Application string   `json:"application"`
	OS          string   `json:"os"`
	Version     string   `json:"version"`
	Tags        []string `json:"tags"`
	Confidence  float64  `json:"confidence"`
}

type HeaderPattern struct {
	Name        string            `json:"name"`
	Headers     map[string]string `json:"headers"`
	Order       []string          `json:"order"`
	Application string            `json:"application"`
	Version     string            `json:"version"`
	Confidence  float64           `json:"confidence"`
}

type UserAgentDatabase struct {
	Patterns    map[string]*UAPattern `json:"patterns"`
	LastUpdated time.Time             `json:"last_updated"`
	Version     string                `json:"version"`
}

type UAPattern struct {
	Pattern    string  `json:"pattern"`
	Browser    string  `json:"browser"`
	Version    string  `json:"version"`
	OS         string  `json:"os"`
	Device     string  `json:"device"`
	Bot        bool    `json:"bot"`
	Confidence float64 `json:"confidence"`
}

type RequestPatterns struct {
	Methods       map[string]int `json:"methods"`
	ContentTypes  map[string]int `json:"content_types"`
	UserAgents    []string       `json:"user_agents"`
	Referrers     []string       `json:"referrers"`
	RequestSizes  []int64        `json:"request_sizes"`
	ResponseCodes map[int]int    `json:"response_codes"`
	Frequency     float64        `json:"frequency"`
	Regularity    float64        `json:"regularity"`
}

type InteractionData struct {
	MouseMovements   []*MouseMovement   `json:"mouse_movements"`
	KeyboardEvents   []*KeyboardEvent   `json:"keyboard_events"`
	TouchEvents      []*TouchEvent      `json:"touch_events"`
	ScrollEvents     []*ScrollEvent     `json:"scroll_events"`
	FormInteractions []*FormInteraction `json:"form_interactions"`
}

type NavigationFlow struct {
	Pages         []string       `json:"pages"`
	Transitions   map[string]int `json:"transitions"`
	EntryPoints   map[string]int `json:"entry_points"`
	ExitPoints    map[string]int `json:"exit_points"`
	SessionDepth  int            `json:"session_depth"`
	BacktrackRate float64        `json:"backtrack_rate"`
}

type MouseMovement struct {
	X         int       `json:"x"`
	Y         int       `json:"y"`
	Timestamp time.Time `json:"timestamp"`
	Velocity  float64   `json:"velocity"`
	Pressure  float64   `json:"pressure"`
}

type KeyboardEvent struct {
	Key       string        `json:"key"`
	Type      string        `json:"type"`
	Timestamp time.Time     `json:"timestamp"`
	Duration  time.Duration `json:"duration"`
}

type TouchEvent struct {
	X         int       `json:"x"`
	Y         int       `json:"y"`
	Type      string    `json:"type"`
	Pressure  float64   `json:"pressure"`
	Timestamp time.Time `json:"timestamp"`
}

type ScrollEvent struct {
	DeltaX    int       `json:"delta_x"`
	DeltaY    int       `json:"delta_y"`
	Timestamp time.Time `json:"timestamp"`
}

type FormInteraction struct {
	FieldID     string        `json:"field_id"`
	FieldType   string        `json:"field_type"`
	Action      string        `json:"action"`
	Value       string        `json:"value"`
	FillTime    time.Duration `json:"fill_time"`
	Corrections int           `json:"corrections"`
	Timestamp   time.Time     `json:"timestamp"`
}

type ChallengeType struct {
	ID          string                     `json:"id"`
	Name        string                     `json:"name"`
	Type        string                     `json:"type"`
	Difficulty  int                        `json:"difficulty"`
	Description string                     `json:"description"`
	Parameters  map[string]interface{}     `json:"parameters"`
	Success     func(response string) bool `json:"-"`
	Generate    func() (string, string)    `json:"-"`
}

type ChallengeResponse struct {
	ChallengeID string        `json:"challenge_id"`
	Response    string        `json:"response"`
	Timestamp   time.Time     `json:"timestamp"`
	IP          string        `json:"ip"`
	UserAgent   string        `json:"user_agent"`
	Correct     bool          `json:"correct"`
	Duration    time.Duration `json:"duration"`
}

// Model and processing types
type ModelPerformance struct {
	Accuracy  float64 `json:"accuracy"`
	Precision float64 `json:"precision"`
	Recall    float64 `json:"recall"`
	F1Score   float64 `json:"f1_score"`
	AUC       float64 `json:"auc"`
	MAE       float64 `json:"mae"`
	RMSE      float64 `json:"rmse"`
}

type ProcessingRule struct {
	ID         string                 `json:"id"`
	Name       string                 `json:"name"`
	Condition  string                 `json:"condition"`
	Action     string                 `json:"action"`
	Parameters map[string]interface{} `json:"parameters"`
	Priority   int                    `json:"priority"`
	Enabled    bool                   `json:"enabled"`
}

type EventProcessor struct {
	ID        string              `json:"id"`
	Name      string              `json:"name"`
	Type      string              `json:"type"`
	Rules     []*ProcessingRule   `json:"rules"`
	Filters   []*EventFilter      `json:"filters"`
	Enrichers []*EventEnricher    `json:"enrichers"`
	Output    chan *SecurityEvent `json:"-"`
	Config    *ProcessorConfig    `json:"config"`
	Stats     *ProcessorStats     `json:"stats"`
}

type EventFilter struct {
	ID         string                 `json:"id"`
	Name       string                 `json:"name"`
	Type       string                 `json:"type"`
	Condition  string                 `json:"condition"`
	Parameters map[string]interface{} `json:"parameters"`
	Enabled    bool                   `json:"enabled"`
}

type EventEnricher struct {
	ID         string                 `json:"id"`
	Name       string                 `json:"name"`
	Type       string                 `json:"type"`
	Source     string                 `json:"source"`
	Fields     []string               `json:"fields"`
	Parameters map[string]interface{} `json:"parameters"`
	Enabled    bool                   `json:"enabled"`
}

type ProcessorConfig struct {
	BufferSize    int           `json:"buffer_size"`
	Workers       int           `json:"workers"`
	FlushInterval time.Duration `json:"flush_interval"`
	MaxRetries    int           `json:"max_retries"`
	Timeout       time.Duration `json:"timeout"`
}

type ProcessorStats struct {
	ProcessedEvents uint64        `json:"processed_events"`
	FilteredEvents  uint64        `json:"filtered_events"`
	EnrichedEvents  uint64        `json:"enriched_events"`
	ErrorCount      uint64        `json:"error_count"`
	AverageLatency  time.Duration `json:"average_latency"`
	Throughput      float64       `json:"throughput"`
	LastProcessed   time.Time     `json:"last_processed"`
}

type SecurityEvent struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"`
	Category    string                 `json:"category"`
	Severity    string                 `json:"severity"`
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	Source      *EventSource           `json:"source"`
	Target      *EventTarget           `json:"target"`
	Actor       *ThreatActor           `json:"actor"`
	IOCs        []*IOC                 `json:"iocs"`
	TTPs        []*TTP                 `json:"ttps"`
	Evidence    map[string]interface{} `json:"evidence"`
	Metadata    map[string]interface{} `json:"metadata"`
	Confidence  float64                `json:"confidence"`
	Impact      string                 `json:"impact"`
	Status      string                 `json:"status"`
	Assignee    string                 `json:"assignee"`
	Tags        []string               `json:"tags"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
	ResolvedAt  *time.Time             `json:"resolved_at"`
}

type EventSource struct {
	Type     string                 `json:"type"`
	Name     string                 `json:"name"`
	IP       string                 `json:"ip"`
	Hostname string                 `json:"hostname"`
	Location *GeoLocation           `json:"location"`
	Metadata map[string]interface{} `json:"metadata"`
}

type EventTarget struct {
	Type     string                 `json:"type"`
	Name     string                 `json:"name"`
	IP       string                 `json:"ip"`
	Hostname string                 `json:"hostname"`
	Service  string                 `json:"service"`
	Port     int                    `json:"port"`
	Metadata map[string]interface{} `json:"metadata"`
}

type DashboardWidget struct {
	ID          string          `json:"id"`
	Type        string          `json:"type"`
	Title       string          `json:"title"`
	Description string          `json:"description"`
	Config      *WidgetConfig   `json:"config"`
	Data        interface{}     `json:"data"`
	Position    *WidgetPosition `json:"position"`
	Filters     []*WidgetFilter `json:"filters"`
	RefreshRate time.Duration   `json:"refresh_rate"`
	LastUpdated time.Time       `json:"last_updated"`
}

type WidgetConfig struct {
	DataSource    string                 `json:"data_source"`
	Query         string                 `json:"query"`
	Visualization string                 `json:"visualization"`
	TimeRange     *TimeRange             `json:"time_range"`
	GroupBy       []string               `json:"group_by"`
	Aggregation   string                 `json:"aggregation"`
	Limit         int                    `json:"limit"`
	Parameters    map[string]interface{} `json:"parameters"`
}

type WidgetPosition struct {
	X      int `json:"x"`
	Y      int `json:"y"`
	Width  int `json:"width"`
	Height int `json:"height"`
}

type WidgetFilter struct {
	Field    string      `json:"field"`
	Operator string      `json:"operator"`
	Value    interface{} `json:"value"`
	Enabled  bool        `json:"enabled"`
}

type DashboardLayout struct {
	Type    string `json:"type"`
	Columns int    `json:"columns"`
	Rows    int    `json:"rows"`
	Spacing int    `json:"spacing"`
}

type DashboardFilter struct {
	ID       string      `json:"id"`
	Name     string      `json:"name"`
	Type     string      `json:"type"`
	Field    string      `json:"field"`
	Operator string      `json:"operator"`
	Value    interface{} `json:"value"`
	Global   bool        `json:"global"`
	Enabled  bool        `json:"enabled"`
}

// Additional utility types
type EventMetrics struct {
	TotalEvents     uint64        `json:"total_events"`
	EventsPerSecond float64       `json:"events_per_second"`
	AverageLatency  time.Duration `json:"average_latency"`
	ErrorRate       float64       `json:"error_rate"`
	LastEvent       time.Time     `json:"last_event"`
}

type SystemHealth struct {
	Status    string            `json:"status"`
	Uptime    time.Duration     `json:"uptime"`
	CPU       float64           `json:"cpu"`
	Memory    float64           `json:"memory"`
	Disk      float64           `json:"disk"`
	Network   *NetworkStats     `json:"network"`
	Services  map[string]string `json:"services"`
	Alerts    []*HealthAlert    `json:"alerts"`
	LastCheck time.Time         `json:"last_check"`
}

type NetworkStats struct {
	BytesIn     uint64  `json:"bytes_in"`
	BytesOut    uint64  `json:"bytes_out"`
	PacketsIn   uint64  `json:"packets_in"`
	PacketsOut  uint64  `json:"packets_out"`
	ErrorsIn    uint64  `json:"errors_in"`
	ErrorsOut   uint64  `json:"errors_out"`
	Utilization float64 `json:"utilization"`
}

type HealthAlert struct {
	ID           string    `json:"id"`
	Type         string    `json:"type"`
	Severity     string    `json:"severity"`
	Message      string    `json:"message"`
	Component    string    `json:"component"`
	Threshold    float64   `json:"threshold"`
	Current      float64   `json:"current"`
	Timestamp    time.Time `json:"timestamp"`
	Acknowledged bool      `json:"acknowledged"`
}

// Bot protection and challenge types
type FeedbackLoop struct {
	ID         string                 `json:"id"`
	Type       string                 `json:"type"`
	Source     string                 `json:"source"`
	Target     string                 `json:"target"`
	Data       map[string]interface{} `json:"data"`
	Confidence float64                `json:"confidence"`
	Action     string                 `json:"action"`
	Timestamp  time.Time              `json:"timestamp"`
}

type CAPTCHAEngine struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"`
	Difficulty  string                 `json:"difficulty"`
	Provider    string                 `json:"provider"`
	Config      map[string]interface{} `json:"config"`
	SuccessRate float64                `json:"success_rate"`
	Status      string                 `json:"status"`
}

type JavaScriptChallenge struct {
	ID         string        `json:"id"`
	Type       string        `json:"type"`
	Code       string        `json:"code"`
	Complexity int           `json:"complexity"`
	Timeout    time.Duration `json:"timeout"`
	Expected   string        `json:"expected"`
	Status     string        `json:"status"`
}

type ProofOfWorkChallenge struct {
	ID         string        `json:"id"`
	Type       string        `json:"type"`
	Difficulty int           `json:"difficulty"`
	Target     string        `json:"target"`
	Nonce      string        `json:"nonce"`
	Timeout    time.Duration `json:"timeout"`
	Status     string        `json:"status"`
}

type BiometricChallenge struct {
	ID         string                 `json:"id"`
	Type       string                 `json:"type"`
	Method     string                 `json:"method"`
	Data       map[string]interface{} `json:"data"`
	Confidence float64                `json:"confidence"`
	Status     string                 `json:"status"`
}

type PuzzleChallenge struct {
	ID         string                 `json:"id"`
	Type       string                 `json:"type"`
	Puzzle     map[string]interface{} `json:"puzzle"`
	Solution   string                 `json:"solution"`
	Difficulty int                    `json:"difficulty"`
	Status     string                 `json:"status"`
}

type GameBasedChallenge struct {
	ID        string                 `json:"id"`
	Type      string                 `json:"type"`
	Game      string                 `json:"game"`
	Level     int                    `json:"level"`
	Objective string                 `json:"objective"`
	Data      map[string]interface{} `json:"data"`
	Status    string                 `json:"status"`
}

type InvisibleChallenge struct {
	ID     string                 `json:"id"`
	Type   string                 `json:"type"`
	Method string                 `json:"method"`
	Hidden bool                   `json:"hidden"`
	Data   map[string]interface{} `json:"data"`
	Status string                 `json:"status"`
}

type AdaptiveChallenge struct {
	ID         string                 `json:"id"`
	Type       string                 `json:"type"`
	Algorithm  string                 `json:"algorithm"`
	Adaptation map[string]interface{} `json:"adaptation"`
	Learning   bool                   `json:"learning"`
	Status     string                 `json:"status"`
}

type IPReputationSystem struct {
	ID       string                 `json:"id"`
	Type     string                 `json:"type"`
	Provider string                 `json:"provider"`
	Sources  []string               `json:"sources"`
	Cache    map[string]interface{} `json:"cache"`
	TTL      time.Duration          `json:"ttl"`
	Status   string                 `json:"status"`
}

// Missing types for BotProtectionEngine
type AntiAutomationSuite struct {
	Enabled           bool     `yaml:"enabled"`
	DetectionMethods  []string `yaml:"detection_methods"`
	PreventionActions []string `yaml:"prevention_actions"`
	Threshold         float64  `yaml:"threshold"`
}

type ChallengeOrchestrator struct {
	Enabled              bool     `yaml:"enabled"`
	ChallengeTypes       []string `yaml:"challenge_types"`
	DifficultyAdjustment bool     `yaml:"difficulty_adjustment"`
	SuccessThreshold     float64  `yaml:"success_threshold"`
}

type BehaviorEngine struct {
	Enabled         bool          `yaml:"enabled"`
	AnalysisMode    string        `yaml:"analysis_mode"`
	LearningEnabled bool          `yaml:"learning_enabled"`
	UpdateInterval  time.Duration `yaml:"update_interval"`
}

type FingerprintSuite struct {
	Enabled            bool     `yaml:"enabled"`
	FingerprintMethods []string `yaml:"fingerprint_methods"`
	PersistenceLevel   string   `yaml:"persistence_level"`
	AntiEvasion        bool     `yaml:"anti_evasion"`
}

// Advanced Bot Detection and Mitigation
type BotProtectionEngine struct {
	Enabled               bool                   `yaml:"enabled"`
	StrictMode            bool                   `yaml:"strict_mode"`
	AntiAutomationSuite   *AntiAutomationSuite   `yaml:"anti_automation_suite"`
	ChallengeOrchestrator *ChallengeOrchestrator `yaml:"challenge_orchestrator"`
	BehaviorEngine        *BehaviorEngine        `yaml:"behavior_engine"`
	FingerprintSuite      *FingerprintSuite      `yaml:"fingerprint_suite"`
	ReputationEngine      *ReputationEngine      `yaml:"reputation_engine"`
	DeviceProfilingSystem *DeviceProfilingSystem `yaml:"device_profiling_system"`
}

// Device Profiling and Analysis
type DeviceProfilingSystem struct {
	HardwareProfiler       *HardwareProfiler       `yaml:"hardware_profiler"`
	SoftwareProfiler       *SoftwareProfiler       `yaml:"software_profiler"`
	EnvironmentProfiler    *EnvironmentProfiler    `yaml:"environment_profiler"`
	VirtualizationDetector *VirtualizationDetector `yaml:"virtualization_detector"`
	EmulationDetector      *EmulationDetector      `yaml:"emulation_detector"`
}

type HardwareProfiler struct {
	Enabled          bool `yaml:"enabled"`
	CPUProfiling     bool `yaml:"cpu_profiling"`
	GPUProfiling     bool `yaml:"gpu_profiling"`
	MemoryProfiling  bool `yaml:"memory_profiling"`
	StorageProfiling bool `yaml:"storage_profiling"`
}

type SoftwareProfiler struct {
	Enabled           bool `yaml:"enabled"`
	OSDetection       bool `yaml:"os_detection"`
	BrowserProfiling  bool `yaml:"browser_profiling"`
	PluginDetection   bool `yaml:"plugin_detection"`
	ExtensionAnalysis bool `yaml:"extension_analysis"`
}

type EnvironmentProfiler struct {
	Enabled           bool `yaml:"enabled"`
	TimezoneAnalysis  bool `yaml:"timezone_analysis"`
	LanguageDetection bool `yaml:"language_detection"`
	NetworkProfiling  bool `yaml:"network_profiling"`
	LocationAnalysis  bool `yaml:"location_analysis"`
}

type VirtualizationDetector struct {
	Enabled            bool `yaml:"enabled"`
	VMDetection        bool `yaml:"vm_detection"`
	ContainerDetection bool `yaml:"container_detection"`
	SandboxDetection   bool `yaml:"sandbox_detection"`
	EmulatorDetection  bool `yaml:"emulator_detection"`
}

type EmulationDetector struct {
	Enabled               bool `yaml:"enabled"`
	HeadlessDetection     bool `yaml:"headless_detection"`
	AutomationDetection   bool `yaml:"automation_detection"`
	ScriptingDetection    bool `yaml:"scripting_detection"`
	BotFrameworkDetection bool `yaml:"bot_framework_detection"`
}

// Supporting Types
type DeviceScoring struct {
	Algorithm string             `yaml:"algorithm"`
	Factors   []string           `yaml:"factors"`
	Weights   map[string]float64 `yaml:"weights"`
}

type TrustProfile struct {
	DeviceID          string    `yaml:"device_id"`
	TrustScore        float64   `yaml:"trust_score"`
	LastSeen          time.Time `yaml:"last_seen"`
	VerificationLevel string    `yaml:"verification_level"`
}

type ReputationDatabase struct {
	Type             string `yaml:"type"`
	ConnectionString string `yaml:"connection_string"`
	CacheSize        int    `yaml:"cache_size"`
}

type BehaviorScoring struct {
	Algorithm string             `yaml:"algorithm"`
	Factors   []string           `yaml:"factors"`
	Weights   map[string]float64 `yaml:"weights"`
}

type PatternAnalysis struct {
	Enabled    bool          `yaml:"enabled"`
	Algorithms []string      `yaml:"algorithms"`
	WindowSize time.Duration `yaml:"window_size"`
}

type AnomalyDetection struct {
	Enabled          bool    `yaml:"enabled"`
	Threshold        float64 `yaml:"threshold"`
	SensitivityLevel string  `yaml:"sensitivity_level"`
}

// Missing reputation system component types
type DeviceReputationSystem struct {
	Enabled            bool                     `yaml:"enabled"`
	DeviceScoring      *DeviceScoring           `yaml:"device_scoring"`
	TrustProfiles      map[string]*TrustProfile `yaml:"trust_profiles"`
	ReputationDatabase *ReputationDatabase      `yaml:"reputation_database"`
}

type BehaviorReputationSystem struct {
	Enabled          bool              `yaml:"enabled"`
	BehaviorScoring  *BehaviorScoring  `yaml:"behavior_scoring"`
	PatternAnalysis  *PatternAnalysis  `yaml:"pattern_analysis"`
	AnomalyDetection *AnomalyDetection `yaml:"anomaly_detection"`
}

type GlobalReputationSystem struct {
	Enabled        bool               `yaml:"enabled"`
	FeedSources    []string           `yaml:"feed_sources"`
	LocalOverrides map[string]float64 `yaml:"local_overrides"`
	SyncInterval   time.Duration      `yaml:"sync_interval"`
}

type ReputationConsensus struct {
	Enabled           bool   `yaml:"enabled"`
	Algorithm         string `yaml:"algorithm"`
	MinimumSources    int    `yaml:"minimum_sources"`
	WeightingStrategy string `yaml:"weighting_strategy"`
}

type ReputationDecay struct {
	Enabled         bool          `yaml:"enabled"`
	DecayRate       float64       `yaml:"decay_rate"`
	MinimumScore    float64       `yaml:"minimum_score"`
	RefreshInterval time.Duration `yaml:"refresh_interval"`
}

// Missing automation and dynamics detection types
type AutomationDetector struct {
	Enabled          bool     `yaml:"enabled"`
	DetectionMethods []string `yaml:"detection_methods"`
	Sensitivity      string   `yaml:"sensitivity"`
	BypassDetection  bool     `yaml:"bypass_detection"`
}

type KeystrokeDynamics struct {
	Enabled        bool          `yaml:"enabled"`
	AnalysisWindow time.Duration `yaml:"analysis_window"`
	MinSamples     int           `yaml:"min_samples"`
	Threshold      float64       `yaml:"threshold"`
}

type MouseDynamics struct {
	Enabled           bool          `yaml:"enabled"`
	TrackingPrecision string        `yaml:"tracking_precision"`
	SamplingRate      time.Duration `yaml:"sampling_rate"`
	PatternAnalysis   bool          `yaml:"pattern_analysis"`
}

type TouchDynamics struct {
	Enabled            bool `yaml:"enabled"`
	PressureAnalysis   bool `yaml:"pressure_analysis"`
	GestureRecognition bool `yaml:"gesture_recognition"`
	MultiTouchSupport  bool `yaml:"multi_touch_support"`
}

type GazePrediction struct {
	Enabled             bool    `yaml:"enabled"`
	CalibrationRequired bool    `yaml:"calibration_required"`
	AccuracyThreshold   float64 `yaml:"accuracy_threshold"`
	TrackingMode        string  `yaml:"tracking_mode"`
}

// Additional biometric and analysis types
type VoiceAnalysis struct {
	Enabled           bool          `yaml:"enabled"`
	RecognitionMode   string        `yaml:"recognition_mode"`
	SampleDuration    time.Duration `yaml:"sample_duration"`
	AccuracyThreshold float64       `yaml:"accuracy_threshold"`
}

type BehaviorBiometrics struct {
	Enabled             bool     `yaml:"enabled"`
	BiometricTypes      []string `yaml:"biometric_types"`
	FusionMode          string   `yaml:"fusion_mode"`
	ConfidenceThreshold float64  `yaml:"confidence_threshold"`
}

type FingerprintAnalysis struct {
	Enabled             bool          `yaml:"enabled"`
	AnalysisDepth       string        `yaml:"analysis_depth"`
	ComparisonAlgorithm string        `yaml:"comparison_algorithm"`
	UpdateFrequency     time.Duration `yaml:"update_frequency"`
}

type BehaviorAnalysis struct {
	Enabled          bool   `yaml:"enabled"`
	PatternDetection bool   `yaml:"pattern_detection"`
	AnomalyDetection bool   `yaml:"anomaly_detection"`
	LearningMode     string `yaml:"learning_mode"`
}

type MLClassification struct {
	Enabled           bool     `yaml:"enabled"`
	ModelType         string   `yaml:"model_type"`
	TrainingMode      string   `yaml:"training_mode"`
	FeatureExtraction []string `yaml:"feature_extraction"`
}

type ReputationAnalysis struct {
	Enabled           bool          `yaml:"enabled"`
	DataSources       []string      `yaml:"data_sources"`
	WeightingStrategy string        `yaml:"weighting_strategy"`
	UpdateInterval    time.Duration `yaml:"update_interval"`
}

type DeviceAnalysis struct {
	Enabled        bool   `yaml:"enabled"`
	ProfilingDepth string `yaml:"profiling_depth"`
	ComparisonMode string `yaml:"comparison_mode"`
	StorageMethod  string `yaml:"storage_method"`
}

type BiometricAnalysis struct {
	Enabled           bool     `yaml:"enabled"`
	BiometricMethods  []string `yaml:"biometric_methods"`
	FalsePositiveRate float64  `yaml:"false_positive_rate"`
	AdaptiveLearning  bool     `yaml:"adaptive_learning"`
}

type NetworkAnalysis struct {
	Enabled          bool `yaml:"enabled"`
	TrafficProfiling bool `yaml:"traffic_profiling"`
	ProtocolAnalysis bool `yaml:"protocol_analysis"`
	FlowAnalysis     bool `yaml:"flow_analysis"`
}

type TemporalAnalysis struct {
	Enabled          bool          `yaml:"enabled"`
	WindowSize       time.Duration `yaml:"window_size"`
	PatternDetection bool          `yaml:"pattern_detection"`
	TrendAnalysis    bool          `yaml:"trend_analysis"`
}

// Additional fingerprinting and behavior types
type DetectionExplanation struct {
	Method     string                 `json:"method"`
	Confidence float64                `json:"confidence"`
	Reasoning  string                 `json:"reasoning"`
	Evidence   map[string]interface{} `json:"evidence"`
}

type TLSFingerprint struct {
	Version       string   `json:"version"`
	CipherSuites  []string `json:"cipher_suites"`
	Extensions    []string `json:"extensions"`
	SignatureAlgs []string `json:"signature_algorithms"`
}

type HTTPFingerprint struct {
	UserAgent      string            `json:"user_agent"`
	Headers        map[string]string `json:"headers"`
	AcceptEncoding string            `json:"accept_encoding"`
	AcceptLanguage string            `json:"accept_language"`
}

type BrowserFingerprint struct {
	Name             string   `json:"name"`
	Version          string   `json:"version"`
	Platform         string   `json:"platform"`
	Plugins          []string `json:"plugins"`
	ScreenResolution string   `json:"screen_resolution"`
}

type FontFingerprint struct {
	AvailableFonts  []string           `json:"available_fonts"`
	RenderingEngine string             `json:"rendering_engine"`
	FontMetrics     map[string]float64 `json:"font_metrics"`
}

type TimingFingerprint struct {
	DNSTime      time.Duration `json:"dns_time"`
	ConnectTime  time.Duration `json:"connect_time"`
	TLSTime      time.Duration `json:"tls_time"`
	ResponseTime time.Duration `json:"response_time"`
}

type MouseBehavior struct {
	MovementPattern string  `json:"movement_pattern"`
	ClickFrequency  float64 `json:"click_frequency"`
	Velocity        float64 `json:"velocity"`
	Acceleration    float64 `json:"acceleration"`
}

type KeyboardBehavior struct {
	TypingSpeed float64       `json:"typing_speed"`
	DwellTime   time.Duration `json:"dwell_time"`
	FlightTime  time.Duration `json:"flight_time"`
	Rhythm      []float64     `json:"rhythm"`
}

type ScrollBehavior struct {
	ScrollSpeed   float64 `json:"scroll_speed"`
	ScrollPattern string  `json:"scroll_pattern"`
	Direction     string  `json:"direction"`
	Frequency     float64 `json:"frequency"`
}

type ClickPatterns struct {
	ClickRate       float64       `json:"click_rate"`
	DoubleClickTime time.Duration `json:"double_click_time"`
	ClickPressure   float64       `json:"click_pressure"`
	ClickAccuracy   float64       `json:"click_accuracy"`
}

// Additional navigation and interaction types
type NavigationPatterns struct {
	PageSequence  []string        `json:"page_sequence"`
	DwellTimes    []time.Duration `json:"dwell_times"`
	BacktrackRate float64         `json:"backtrack_rate"`
	DepthScore    float64         `json:"depth_score"`
}

type InteractionMetrics struct {
	ClickRate        float64       `json:"click_rate"`
	HoverTime        time.Duration `json:"hover_time"`
	FocusChanges     int           `json:"focus_changes"`
	FormInteractions int           `json:"form_interactions"`
}

type SessionMetrics struct {
	Duration    time.Duration `json:"duration"`
	PageViews   int           `json:"page_views"`
	UniquePages int           `json:"unique_pages"`
	BounceRate  float64       `json:"bounce_rate"`
}

// ML and AI prediction types
type EnsemblePrediction struct {
	Predictions   map[string]float64 `json:"predictions"`
	WeightedScore float64            `json:"weighted_score"`
	Confidence    float64            `json:"confidence"`
	ModelVersions map[string]string  `json:"model_versions"`
}

type DeepLearningResult struct {
	Prediction        float64              `json:"prediction"`
	Layers            []string             `json:"layers"`
	ActivationMap     map[string][]float64 `json:"activation_map"`
	FeatureImportance map[string]float64   `json:"feature_importance"`
}

type GradientBoostingResult struct {
	Prediction    float64            `json:"prediction"`
	TreeCount     int                `json:"tree_count"`
	FeatureScores map[string]float64 `json:"feature_scores"`
	SplitPoints   []float64          `json:"split_points"`
}

type NeuralNetworkResult struct {
	Prediction   float64     `json:"prediction"`
	NetworkDepth int         `json:"network_depth"`
	Neurons      []int       `json:"neurons"`
	Weights      [][]float64 `json:"weights"`
}

type TransformerResult struct {
	Prediction       float64              `json:"prediction"`
	AttentionWeights map[string][]float64 `json:"attention_weights"`
	TokenEmbeddings  [][]float64          `json:"token_embeddings"`
	SequenceLength   int                  `json:"sequence_length"`
}

// HTTP analysis types
type UserAgentAnalysis struct {
	Browser    string  `json:"browser"`
	Version    string  `json:"version"`
	OS         string  `json:"os"`
	Suspicious bool    `json:"suspicious"`
	Entropy    float64 `json:"entropy"`
}

type AcceptHeaders struct {
	Language    string `json:"language"`
	Encoding    string `json:"encoding"`
	ContentType string `json:"content_type"`
	Charset     string `json:"charset"`
}

// Additional behavioral and technical types
type ConnectionBehavior struct {
	ConnectTime   time.Duration `json:"connect_time"`
	KeepAlive     bool          `json:"keep_alive"`
	RequestRate   float64       `json:"request_rate"`
	SessionLength time.Duration `json:"session_length"`
}

type Plugin struct {
	Name      string   `json:"name"`
	Version   string   `json:"version"`
	Enabled   bool     `json:"enabled"`
	MimeTypes []string `json:"mime_types"`
}

type MimeType struct {
	Type       string            `json:"type"`
	Subtype    string            `json:"subtype"`
	Parameters map[string]string `json:"parameters"`
}

type TouchSupport struct {
	Enabled         bool `json:"enabled"`
	MaxPoints       int  `json:"max_points"`
	PressureSupport bool `json:"pressure_support"`
}

type WebRTCCapabilities struct {
	Supported  bool     `json:"supported"`
	Codecs     []string `json:"codecs"`
	Extensions []string `json:"extensions"`
}

type BatteryInfo struct {
	Charging      bool    `json:"charging"`
	Level         float64 `json:"level"`
	DischargeTime float64 `json:"discharge_time"`
}

type VelocityStats struct {
	Average float64 `json:"average"`
	Maximum float64 `json:"maximum"`
	Minimum float64 `json:"minimum"`
	StdDev  float64 `json:"std_dev"`
}

type AccelerationStats struct {
	Average float64 `json:"average"`
	Maximum float64 `json:"maximum"`
	Minimum float64 `json:"minimum"`
	Peaks   int     `json:"peaks"`
}

type JerkStats struct {
	Average    float64 `json:"average"`
	Frequency  float64 `json:"frequency"`
	Smoothness float64 `json:"smoothness"`
}
