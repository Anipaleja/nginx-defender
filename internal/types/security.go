package types

import (
	"time"
)

// Hunting specific types
type HuntTool struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Type        string                 `json:"type"`
	Version     string                 `json:"version"`
	Description string                 `json:"description"`
	Category    string                 `json:"category"`
	Capabilities []string              `json:"capabilities"`
	Parameters  map[string]interface{} `json:"parameters"`
	Config      map[string]interface{} `json:"config"`
	Status      string                 `json:"status"`
	LastUsed    time.Time              `json:"last_used"`
	Performance *ToolPerformance       `json:"performance"`
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
	ID          string         `json:"id"`
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Category    string         `json:"category"`
	Author      string         `json:"author"`
	Version     string         `json:"version"`
	Tags        []string       `json:"tags"`
	Steps       []*PlaybookStep `json:"steps"`
	Variables   map[string]interface{} `json:"variables"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
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
	ID          string                 `json:"id"`
	QueryID     string                 `json:"query_id"`
	SessionID   string                 `json:"session_id"`
	Status      string                 `json:"status"`
	Results     []map[string]interface{} `json:"results"`
	Count       int                    `json:"count"`
	ExecutionTime time.Duration        `json:"execution_time"`
	Error       string                 `json:"error"`
	StartedAt   time.Time              `json:"started_at"`
	CompletedAt time.Time              `json:"completed_at"`
}

type HuntingSession struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Hypothesis  string            `json:"hypothesis"`
	Status      string            `json:"status"`
	Hunter      string            `json:"hunter"`
	Queries     []string          `json:"queries"`
	Findings    []*Finding        `json:"findings"`
	TimeRange   *TimeRange        `json:"time_range"`
	Tags        []string          `json:"tags"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
}

type Finding struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"`
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	Severity    string                 `json:"severity"`
	Confidence  float64                `json:"confidence"`
	Evidence    []map[string]interface{} `json:"evidence"`
	IOCs        []*IOC                 `json:"iocs"`
	TTPs        []*TTP                 `json:"ttps"`
	Metadata    map[string]interface{} `json:"metadata"`
	CreatedAt   time.Time              `json:"created_at"`
}

// Protection specific types
type TLSFingerprintAnalyzer struct {
	SupportedVersions []string              `json:"supported_versions"`
	CipherSuites      map[string][]string   `json:"cipher_suites"`
	Extensions        map[string][]string   `json:"extensions"`
	Patterns          map[string]*TLSPattern `json:"patterns"`
	Database          *FingerprintDatabase  `json:"database"`
}

type TLSPattern struct {
	Name        string   `json:"name"`
	Version     string   `json:"version"`
	Ciphers     []string `json:"ciphers"`
	Extensions  []string `json:"extensions"`
	Curve       string   `json:"curve"`
	Signature   string   `json:"signature"`
	Confidence  float64  `json:"confidence"`
}

type FingerprintDatabase struct {
	Fingerprints map[string]*ClientFingerprint `json:"fingerprints"`
	LastUpdated  time.Time                     `json:"last_updated"`
	Version      string                        `json:"version"`
	Source       string                        `json:"source"`
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
	Pattern     string  `json:"pattern"`
	Browser     string  `json:"browser"`
	Version     string  `json:"version"`
	OS          string  `json:"os"`
	Device      string  `json:"device"`
	Bot         bool    `json:"bot"`
	Confidence  float64 `json:"confidence"`
}

type SecurityAnomaly struct {
	Type        string                 `json:"type"`
	Description string                 `json:"description"`
	Severity    string                 `json:"severity"`
	Score       float64                `json:"score"`
	Evidence    map[string]interface{} `json:"evidence"`
	Timestamp   time.Time              `json:"timestamp"`
}

type SecurityBehaviorProfile struct {
	UserID          string                 `json:"user_id"`
	SessionID       string                 `json:"session_id"`
	RequestPatterns *RequestPatterns       `json:"request_patterns"`
	NavigationFlow  *NavigationFlow        `json:"navigation_flow"`
	TimingProfile   *TimingProfile         `json:"timing_profile"`
	InteractionData *InteractionData       `json:"interaction_data"`
	Anomalies       []*SecurityAnomaly     `json:"anomalies"`
	Score           float64                `json:"score"`
	Classification  string                 `json:"classification"`
	LastUpdated     time.Time              `json:"last_updated"`
}

type RequestPatterns struct {
	Methods       map[string]int    `json:"methods"`
	ContentTypes  map[string]int    `json:"content_types"`
	UserAgents    []string          `json:"user_agents"`
	Referrers     []string          `json:"referrers"`
	RequestSizes  []int64           `json:"request_sizes"`
	ResponseCodes map[int]int       `json:"response_codes"`
	Frequency     float64           `json:"frequency"`
	Regularity    float64           `json:"regularity"`
}

type InteractionData struct {
	MouseMovements   []*MouseMovement   `json:"mouse_movements"`
	KeyboardEvents   []*KeyboardEvent   `json:"keyboard_events"`
	TouchEvents      []*TouchEvent      `json:"touch_events"`
	ScrollEvents     []*ScrollEvent     `json:"scroll_events"`
	FormInteractions []*FormInteraction `json:"form_interactions"`
}

type NavigationFlow struct {
	Pages         []string          `json:"pages"`
	Transitions   map[string]int    `json:"transitions"`
	EntryPoints   map[string]int    `json:"entry_points"`
	ExitPoints    map[string]int    `json:"exit_points"`
	SessionDepth  int               `json:"session_depth"`
	BacktrackRate float64           `json:"backtrack_rate"`
}

type MouseMovement struct {
	X         int       `json:"x"`
	Y         int       `json:"y"`
	Timestamp time.Time `json:"timestamp"`
	Velocity  float64   `json:"velocity"`
	Pressure  float64   `json:"pressure"`
}

type KeyboardEvent struct {
	Key       string    `json:"key"`
	Type      string    `json:"type"`
	Timestamp time.Time `json:"timestamp"`
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
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Type        string                 `json:"type"`
	Difficulty  int                    `json:"difficulty"`
	Description string                 `json:"description"`
	Parameters  map[string]interface{} `json:"parameters"`
	Success     func(response string) bool `json:"-"`
	Generate    func() (string, string) `json:"-"`
}

type ChallengeResponse struct {
	ChallengeID string    `json:"challenge_id"`
	Response    string    `json:"response"`
	Timestamp   time.Time `json:"timestamp"`
	IP          string    `json:"ip"`
	UserAgent   string    `json:"user_agent"`
	Correct     bool      `json:"correct"`
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
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Condition   string                 `json:"condition"`
	Action      string                 `json:"action"`
	Parameters  map[string]interface{} `json:"parameters"`
	Priority    int                    `json:"priority"`
	Enabled     bool                   `json:"enabled"`
}

type EventProcessor struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Type        string                 `json:"type"`
	Rules       []*ProcessingRule      `json:"rules"`
	Filters     []*EventFilter         `json:"filters"`
	Enrichers   []*EventEnricher       `json:"enrichers"`
	Output      chan *SecurityEvent    `json:"-"`
	Config      *ProcessorConfig       `json:"config"`
	Stats       *ProcessorStats        `json:"stats"`
}

type EventFilter struct {
	ID        string                 `json:"id"`
	Name      string                 `json:"name"`
	Type      string                 `json:"type"`
	Condition string                 `json:"condition"`
	Parameters map[string]interface{} `json:"parameters"`
	Enabled   bool                   `json:"enabled"`
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
	Type        string            `json:"type"`
	Name        string            `json:"name"`
	IP          string            `json:"ip"`
	Hostname    string            `json:"hostname"`
	Location    *GeoLocation      `json:"location"`
	Metadata    map[string]interface{} `json:"metadata"`
}

type EventTarget struct {
	Type        string            `json:"type"`
	Name        string            `json:"name"`
	IP          string            `json:"ip"`
	Hostname    string            `json:"hostname"`
	Service     string            `json:"service"`
	Port        int               `json:"port"`
	Metadata    map[string]interface{} `json:"metadata"`
}

type DashboardWidget struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"`
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	Config      *WidgetConfig          `json:"config"`
	Data        interface{}            `json:"data"`
	Position    *WidgetPosition        `json:"position"`
	Filters     []*WidgetFilter        `json:"filters"`
	RefreshRate time.Duration          `json:"refresh_rate"`
	LastUpdated time.Time              `json:"last_updated"`
}

type WidgetConfig struct {
	DataSource   string                 `json:"data_source"`
	Query        string                 `json:"query"`
	Visualization string                `json:"visualization"`
	TimeRange    *TimeRange             `json:"time_range"`
	GroupBy      []string               `json:"group_by"`
	Aggregation  string                 `json:"aggregation"`
	Limit        int                    `json:"limit"`
	Parameters   map[string]interface{} `json:"parameters"`
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
	Status      string                 `json:"status"`
	Uptime      time.Duration          `json:"uptime"`
	CPU         float64                `json:"cpu"`
	Memory      float64                `json:"memory"`
	Disk        float64                `json:"disk"`
	Network     *NetworkStats          `json:"network"`
	Services    map[string]string      `json:"services"`
	Alerts      []*HealthAlert         `json:"alerts"`
	LastCheck   time.Time              `json:"last_check"`
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
	ID          string    `json:"id"`
	Type        string    `json:"type"`
	Severity    string    `json:"severity"`
	Message     string    `json:"message"`
	Component   string    `json:"component"`
	Threshold   float64   `json:"threshold"`
	Current     float64   `json:"current"`
	Timestamp   time.Time `json:"timestamp"`
	Acknowledged bool     `json:"acknowledged"`
}
