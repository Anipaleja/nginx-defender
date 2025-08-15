package types

import (
	"time"
	"context"
	"fmt"
)

// Common types used across all packages

// Data structures
type DataSource struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Type        string            `json:"type"`
	Connection  string            `json:"connection"`
	Credentials map[string]string `json:"credentials"`
	Config      map[string]interface{} `json:"config"`
}

type TimeRange struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

type GeoLocation struct {
	Country   string  `json:"country"`
	Region    string  `json:"region"`
	City      string  `json:"city"`
	Latitude  float64 `json:"latitude"`
	Longitude float64 `json:"longitude"`
	ISP       string  `json:"isp"`
	ASN       string  `json:"asn"`
}

// Request and Response structures
type RequestData struct {
	Method    string            `json:"method"`
	URL       string            `json:"url"`
	Headers   map[string]string `json:"headers"`
	Body      string            `json:"body"`
	UserAgent string            `json:"user_agent"`
	Timestamp time.Time         `json:"timestamp"`
}

type NetworkData struct {
	SourceIP      string `json:"source_ip"`
	DestinationIP string `json:"destination_ip"`
	SourcePort    int    `json:"source_port"`
	DestPort      int    `json:"dest_port"`
	Protocol      string `json:"protocol"`
}

type InputVector struct {
	RequestData *RequestData `json:"request_data"`
	NetworkData *NetworkData `json:"network_data"`
}

// AI and ML types
type NeuralNetwork struct {
	Layers     []*Layer      `json:"layers"`
	Weights    [][]float64   `json:"weights"`
	Biases     []float64     `json:"biases"`
	Activation string        `json:"activation"`
	Config     *NetworkConfig `json:"config"`
}

type Layer struct {
	Size       int     `json:"size"`
	Type       string  `json:"type"`
	Activation string  `json:"activation"`
	Dropout    float64 `json:"dropout"`
}

type NetworkConfig struct {
	LearningRate  float64 `json:"learning_rate"`
	BatchSize     int     `json:"batch_size"`
	Epochs        int     `json:"epochs"`
	Optimizer     string  `json:"optimizer"`
	LossFunction  string  `json:"loss_function"`
}

type TrainingPoint struct {
	Input     []float64 `json:"input"`
	Output    []float64 `json:"output"`
	Timestamp time.Time `json:"timestamp"`
	Label     string    `json:"label"`
}

type Model interface {
	Train(data []*TrainingPoint) error
	Predict(input []float64) ([]float64, error)
	Evaluate(testData []*TrainingPoint) (float64, error)
	Save(path string) error
	Load(path string) error
}

type MetaLearner struct {
	BaseModels []Model       `json:"base_models"`
	Strategy   string        `json:"strategy"`
	Weights    []float64     `json:"weights"`
	Config     *MetaConfig   `json:"config"`
}

type MetaConfig struct {
	VotingStrategy string  `json:"voting_strategy"`
	Threshold      float64 `json:"threshold"`
	MinConfidence  float64 `json:"min_confidence"`
}

// Semantic Analysis types
type NLPProcessor struct {
	Tokenizer   *Tokenizer   `json:"tokenizer"`
	Parser      *Parser      `json:"parser"`
	Embeddings  *Embeddings  `json:"embeddings"`
	Language    string       `json:"language"`
}

type Tokenizer struct {
	Vocabulary map[string]int `json:"vocabulary"`
	MaxLength  int            `json:"max_length"`
	Padding    string         `json:"padding"`
}

type Parser struct {
	Grammar    map[string]interface{} `json:"grammar"`
	Rules      []string               `json:"rules"`
	Engine     string                 `json:"engine"`
}

type Embeddings struct {
	Vectors   map[string][]float64 `json:"vectors"`
	Dimension int                  `json:"dimension"`
	Model     string               `json:"model"`
}

type CodeAnalyzer struct {
	Languages []string           `json:"languages"`
	Patterns  map[string]*Regex  `json:"patterns"`
	AST       *ASTParser         `json:"ast"`
}

type Regex struct {
	Pattern string `json:"pattern"`
	Flags   string `json:"flags"`
}

type ASTParser struct {
	Language string                 `json:"language"`
	Rules    map[string]interface{} `json:"rules"`
}

type SyntaxParser struct {
	Language string   `json:"language"`
	Grammar  []string `json:"grammar"`
	Tokens   []string `json:"tokens"`
}

type IntentClassifier struct {
	Model      Model              `json:"model"`
	Categories map[string]float64 `json:"categories"`
	Threshold  float64            `json:"threshold"`
}

type SemanticEmbeddings struct {
	Model     string              `json:"model"`
	Vectors   map[string][]float64 `json:"vectors"`
	Dimension int                 `json:"dimension"`
}

// Memory Network types
type ExternalMemory struct {
	Memory     [][]float64 `json:"memory"`
	Size       int         `json:"size"`
	Dimension  int         `json:"dimension"`
	Usage      []float64   `json:"usage"`
}

type MemoryController struct {
	InputProcessor  *NeuralNetwork `json:"input_processor"`
	OutputProcessor *NeuralNetwork `json:"output_processor"`
	State          []float64      `json:"state"`
}

type ReadHead struct {
	Weights    []float64 `json:"weights"`
	KeyVector  []float64 `json:"key_vector"`
	Strength   float64   `json:"strength"`
	Focus      float64   `json:"focus"`
}

type WriteHead struct {
	Weights      []float64 `json:"weights"`
	KeyVector    []float64 `json:"key_vector"`
	Strength     float64   `json:"strength"`
	EraseVector  []float64 `json:"erase_vector"`
	AddVector    []float64 `json:"add_vector"`
}

type NetworkState struct {
	HiddenState []float64 `json:"hidden_state"`
	CellState   []float64 `json:"cell_state"`
	Output      []float64 `json:"output"`
}

// Quantum Computing types
type QuantumCircuit struct {
	Qubits    int                    `json:"qubits"`
	Gates     []*QuantumGate         `json:"gates"`
	Circuit   [][]complex128         `json:"circuit"`
	Prepared  bool                   `json:"prepared"`
}

type QuantumGate struct {
	Type     string      `json:"type"`
	Target   []int       `json:"target"`
	Control  []int       `json:"control"`
	Angle    float64     `json:"angle"`
	Matrix   [][]complex128 `json:"matrix"`
}

type QuantumState struct {
	Amplitudes []complex128 `json:"amplitudes"`
	Qubits     int          `json:"qubits"`
	Normalized bool         `json:"normalized"`
}

type QuantumEntanglement struct {
	Pairs       [][2]int  `json:"pairs"`
	Correlation []float64 `json:"correlation"`
	Strength    float64   `json:"strength"`
}

type QuantumSuperposition struct {
	States      []*QuantumState `json:"states"`
	Weights     []complex128    `json:"weights"`
	Coherence   float64         `json:"coherence"`
}

type QuantumMeasurement struct {
	Basis     string    `json:"basis"`
	Results   []int     `json:"results"`
	Timestamp time.Time `json:"timestamp"`
}

// Security types
type SecurityEntity struct {
	ID           string                 `json:"id"`
	Type         string                 `json:"type"`
	Name         string                 `json:"name"`
	Description  string                 `json:"description"`
	Attributes   map[string]interface{} `json:"attributes"`
	Confidence   float64                `json:"confidence"`
	Source       string                 `json:"source"`
	CreatedAt    time.Time              `json:"created_at"`
	UpdatedAt    time.Time              `json:"updated_at"`
}

type SecurityRelationship struct {
	ID          string    `json:"id"`
	Type        string    `json:"type"`
	Source      string    `json:"source"`
	Target      string    `json:"target"`
	Weight      float64   `json:"weight"`
	Confidence  float64   `json:"confidence"`
	CreatedAt   time.Time `json:"created_at"`
}

type KnowledgeReasoning struct {
	Engine    string                 `json:"engine"`
	Rules     []string               `json:"rules"`
	Facts     map[string]interface{} `json:"facts"`
	Inference *InferenceEngine       `json:"inference"`
}

type InferenceEngine struct {
	Type       string                 `json:"type"`
	Rules      map[string]interface{} `json:"rules"`
	Algorithm  string                 `json:"algorithm"`
	Config     map[string]interface{} `json:"config"`
}

type CyberSecurityOntology struct {
	Classes      map[string]*OntologyClass    `json:"classes"`
	Properties   map[string]*OntologyProperty `json:"properties"`
	Instances    map[string]*OntologyInstance `json:"instances"`
	Namespaces   map[string]string            `json:"namespaces"`
}

type OntologyClass struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Parent      string   `json:"parent"`
	Children    []string `json:"children"`
	Properties  []string `json:"properties"`
	Description string   `json:"description"`
}

type OntologyProperty struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Domain string `json:"domain"`
	Range  string `json:"range"`
	Type   string `json:"type"`
}

type OntologyInstance struct {
	ID         string                 `json:"id"`
	Class      string                 `json:"class"`
	Properties map[string]interface{} `json:"properties"`
}

// Stream Processing types
type StreamProcessor struct {
	BufferSize  int                    `json:"buffer_size"`
	Processors  []*Processor           `json:"processors"`
	Pipeline    *ProcessingPipeline    `json:"pipeline"`
	Config      *StreamConfig          `json:"config"`
}

type Processor struct {
	ID       string                 `json:"id"`
	Type     string                 `json:"type"`
	Function func(interface{}) interface{} `json:"-"`
	Config   map[string]interface{} `json:"config"`
}

type ProcessingPipeline struct {
	Stages    []*ProcessingStage     `json:"stages"`
	Config    *PipelineConfig        `json:"config"`
	Metrics   *PipelineMetrics       `json:"metrics"`
}

type ProcessingStage struct {
	ID         string      `json:"id"`
	Name       string      `json:"name"`
	Processor  *Processor  `json:"processor"`
	Input      chan interface{} `json:"-"`
	Output     chan interface{} `json:"-"`
	Config     *StageConfig `json:"config"`
}

type PipelineConfig struct {
	Parallel    bool   `json:"parallel"`
	BufferSize  int    `json:"buffer_size"`
	Timeout     string `json:"timeout"`
	ErrorPolicy string `json:"error_policy"`
}

type PipelineMetrics struct {
	Throughput   float64   `json:"throughput"`
	Latency      time.Duration `json:"latency"`
	ErrorRate    float64   `json:"error_rate"`
	ProcessedCount uint64  `json:"processed_count"`
	LastUpdate   time.Time `json:"last_update"`
}

type StageConfig struct {
	Parallel   bool          `json:"parallel"`
	Workers    int           `json:"workers"`
	Timeout    time.Duration `json:"timeout"`
	Retries    int           `json:"retries"`
}

type StreamConfig struct {
	BatchSize    int           `json:"batch_size"`
	FlushInterval time.Duration `json:"flush_interval"`
	Compression  bool          `json:"compression"`
	Encryption   bool          `json:"encryption"`
}

type IncrementalModel struct {
	BaseModel    Model         `json:"base_model"`
	UpdateRate   float64       `json:"update_rate"`
	BufferSize   int           `json:"buffer_size"`
	LastUpdate   time.Time     `json:"last_update"`
}

type CircularBuffer struct {
	Data     []interface{} `json:"data"`
	Size     int           `json:"size"`
	Head     int           `json:"head"`
	Tail     int           `json:"tail"`
	Full     bool          `json:"full"`
}

type ThresholdHistory struct {
	History    []float64 `json:"history"`
	MaxSize    int       `json:"max_size"`
	Average    float64   `json:"average"`
	Variance   float64   `json:"variance"`
	Trend      string    `json:"trend"`
}

// Threat Intelligence types
type ThreatActor struct {
	Name          string    `json:"name"`
	Aliases       []string  `json:"aliases"`
	Attribution   string    `json:"attribution"`
	Motivation    []string  `json:"motivation"`
	Capabilities  []string  `json:"capabilities"`
	FirstSeen     time.Time `json:"first_seen"`
	LastActivity  time.Time `json:"last_activity"`
}

type TTP struct {
	TacticID      string   `json:"tactic_id"`
	TacticName    string   `json:"tactic_name"`
	TechniqueID   string   `json:"technique_id"`
	TechniqueName string   `json:"technique_name"`
	SubTechnique  string   `json:"sub_technique"`
	MITREAttackID string   `json:"mitre_attack_id"`
	Procedures    []string `json:"procedures"`
}

type IOC struct {
	Type        string    `json:"type"`
	Value       string    `json:"value"`
	Confidence  float64   `json:"confidence"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	Source      string    `json:"source"`
	Tags        []string  `json:"tags"`
}

type GeopoliticalInfo struct {
	OriginCountry    string   `json:"origin_country"`
	TargetCountries  []string `json:"target_countries"`
	GeopoliticalTensions []string `json:"geopolitical_tensions"`
	EconomicFactors  []string `json:"economic_factors"`
	CyberWarfare     bool     `json:"cyber_warfare"`
}

type Recommendation struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"`
	Priority    string                 `json:"priority"`
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	Actions     []string               `json:"actions"`
	Rationale   string                 `json:"rationale"`
	Evidence    []string               `json:"evidence"`
	Confidence  float64                `json:"confidence"`
	Impact      string                 `json:"impact"`
	Effort      string                 `json:"effort"`
	Timeline    string                 `json:"timeline"`
	Resources   []string               `json:"resources"`
	Dependencies []string              `json:"dependencies"`
	Risks       []string               `json:"risks"`
	Benefits    []string               `json:"benefits"`
	Metadata    map[string]interface{} `json:"metadata"`
	CreatedAt   time.Time              `json:"created_at"`
	ExpiresAt   *time.Time             `json:"expires_at"`
}

// Additional types for missing structures
type TemporalPattern struct {
	Pattern     string    `json:"pattern"`
	Period      time.Duration `json:"period"`
	Frequency   float64   `json:"frequency"`
	Confidence  float64   `json:"confidence"`
	StartTime   time.Time `json:"start_time"`
	EndTime     time.Time `json:"end_time"`
}

type SpatialPattern struct {
	Pattern    string              `json:"pattern"`
	Locations  []*GeoLocation      `json:"locations"`
	Radius     float64             `json:"radius"`
	Confidence float64             `json:"confidence"`
	Metadata   map[string]interface{} `json:"metadata"`
}

type FrequencyAnalysis struct {
	Frequencies map[float64]float64 `json:"frequencies"`
	DominantFreq float64            `json:"dominant_frequency"`
	PowerSpectrum []float64         `json:"power_spectrum"`
	Bandwidth    float64            `json:"bandwidth"`
}

type MemorySlot struct {
	ID        string                 `json:"id"`
	Content   []float64              `json:"content"`
	Usage     float64                `json:"usage"`
	Age       time.Duration          `json:"age"`
	Metadata  map[string]interface{} `json:"metadata"`
	CreatedAt time.Time              `json:"created_at"`
	UpdatedAt time.Time              `json:"updated_at"`
}

type ReasoningStep struct {
	Step       int                    `json:"step"`
	Rule       string                 `json:"rule"`
	Input      map[string]interface{} `json:"input"`
	Output     map[string]interface{} `json:"output"`
	Confidence float64                `json:"confidence"`
	Reasoning  string                 `json:"reasoning"`
}

// Common interfaces
type Analyzer interface {
	Analyze(ctx context.Context, input interface{}) (interface{}, error)
	GetConfig() interface{}
	SetConfig(config interface{}) error
	GetMetrics() interface{}
}

type Engine interface {
	Start(ctx context.Context) error
	Stop(ctx context.Context) error
	Process(ctx context.Context, input interface{}) (interface{}, error)
	GetStatus() string
	GetMetrics() interface{}
}

// HTTP and Web types
type WebSocketConnection struct {
	ID         string
	Connection interface{} // websocket.Conn
	UserID     string
	CreatedAt  time.Time
	LastPing   time.Time
}

type HTTPRequest struct {
	Method     string            `json:"method"`
	URL        string            `json:"url"`
	Headers    map[string]string `json:"headers"`
	Body       string            `json:"body"`
	RemoteAddr string            `json:"remote_addr"`
	UserAgent  string            `json:"user_agent"`
	Timestamp  time.Time         `json:"timestamp"`
}

type HTTPResponse struct {
	StatusCode int               `json:"status_code"`
	Headers    map[string]string `json:"headers"`
	Body       string            `json:"body"`
	Size       int64             `json:"size"`
	Duration   time.Duration     `json:"duration"`
	Timestamp  time.Time         `json:"timestamp"`
}

// Configuration types
type Config struct {
	Server   *ServerConfig   `yaml:"server"`
	Security *SecurityConfig `yaml:"security"`
	AI       *AIConfig       `yaml:"ai"`
	Database *DatabaseConfig `yaml:"database"`
	Logging  *LoggingConfig  `yaml:"logging"`
}

type ServerConfig struct {
	Host         string        `yaml:"host"`
	Port         int           `yaml:"port"`
	ReadTimeout  time.Duration `yaml:"read_timeout"`
	WriteTimeout time.Duration `yaml:"write_timeout"`
	IdleTimeout  time.Duration `yaml:"idle_timeout"`
	TLS          *TLSConfig    `yaml:"tls"`
}

type TLSConfig struct {
	Enabled  bool   `yaml:"enabled"`
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
	MinVersion string `yaml:"min_version"`
	MaxVersion string `yaml:"max_version"`
}

type SecurityConfig struct {
	Authentication *AuthConfig      `yaml:"authentication"`
	Authorization  *AuthzConfig     `yaml:"authorization"`
	Encryption     *EncryptionConfig `yaml:"encryption"`
	RateLimit      *RateLimitConfig `yaml:"rate_limit"`
}

type AuthConfig struct {
	Type       string            `yaml:"type"`
	Providers  map[string]string `yaml:"providers"`
	TokenTTL   time.Duration     `yaml:"token_ttl"`
	RefreshTTL time.Duration     `yaml:"refresh_ttl"`
}

type AuthzConfig struct {
	Type     string            `yaml:"type"`
	Policies map[string]string `yaml:"policies"`
	Rules    []string          `yaml:"rules"`
}

type EncryptionConfig struct {
	Algorithm string `yaml:"algorithm"`
	KeySize   int    `yaml:"key_size"`
	IV        string `yaml:"iv"`
}

type RateLimitConfig struct {
	Rate     int           `yaml:"rate"`
	Burst    int           `yaml:"burst"`
	Window   time.Duration `yaml:"window"`
	Strategy string        `yaml:"strategy"`
}

type AIConfig struct {
	Models    map[string]*ModelConfig `yaml:"models"`
	GPU       bool                    `yaml:"gpu"`
	BatchSize int                     `yaml:"batch_size"`
	Timeout   time.Duration           `yaml:"timeout"`
}

type ModelConfig struct {
	Type       string            `yaml:"type"`
	Path       string            `yaml:"path"`
	Parameters map[string]interface{} `yaml:"parameters"`
	Enabled    bool              `yaml:"enabled"`
}

type DatabaseConfig struct {
	Type         string        `yaml:"type"`
	Host         string        `yaml:"host"`
	Port         int           `yaml:"port"`
	Database     string        `yaml:"database"`
	Username     string        `yaml:"username"`
	Password     string        `yaml:"password"`
	MaxConns     int           `yaml:"max_conns"`
	MaxIdleConns int           `yaml:"max_idle_conns"`
	ConnTimeout  time.Duration `yaml:"conn_timeout"`
}

type LoggingConfig struct {
	Level      string `yaml:"level"`
	Format     string `yaml:"format"`
	Output     string `yaml:"output"`
	File       string `yaml:"file"`
	MaxSize    int    `yaml:"max_size"`
	MaxBackups int    `yaml:"max_backups"`
	MaxAge     int    `yaml:"max_age"`
	Compress   bool   `yaml:"compress"`
}

// Error types
type SecurityError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Details map[string]interface{} `json:"details"`
}

func (e *SecurityError) Error() string {
	return fmt.Sprintf("Security Error [%s]: %s", e.Code, e.Message)
}

type AIError struct {
	Model   string `json:"model"`
	Phase   string `json:"phase"`
	Message string `json:"message"`
	Details map[string]interface{} `json:"details"`
}

func (e *AIError) Error() string {
	return fmt.Sprintf("AI Error [%s/%s]: %s", e.Model, e.Phase, e.Message)
}

// Utility functions
func NewTimeRange(start, end time.Time) *TimeRange {
	return &TimeRange{Start: start, End: end}
}

func NewGeoLocation(country, region, city string, lat, lon float64) *GeoLocation {
	return &GeoLocation{
		Country:   country,
		Region:    region,
		City:      city,
		Latitude:  lat,
		Longitude: lon,
	}
}

func NewRecommendation(rType, priority, title, description string) *Recommendation {
	return &Recommendation{
		ID:          GenerateID(),
		Type:        rType,
		Priority:    priority,
		Title:       title,
		Description: description,
		Actions:     []string{},
		Evidence:    []string{},
		Confidence:  0.0,
		Metadata:    make(map[string]interface{}),
		CreatedAt:   time.Now(),
	}
}

func GenerateID() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}
