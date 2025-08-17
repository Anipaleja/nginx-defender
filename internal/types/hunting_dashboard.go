package types

import (
	"context"
	"fmt"
	"time"
)

// Core interfaces
type Detector interface {
	Detect(ctx context.Context, input interface{}) (bool, float64, error)
	Train(data interface{}) error
	Update(feedback interface{}) error
	GetStats() interface{}
}

// Missing types for hunting package
type IOCEnrichment struct {
	IOC         string                 `json:"ioc"`
	Type        string                 `json:"type"`
	Sources     []string               `json:"sources"`
	Reputation  float64                `json:"reputation"`
	Tags        []string               `json:"tags"`
	Attribution []string               `json:"attribution"`
	Context     map[string]interface{} `json:"context"`
}

type ThreatIntelligence struct {
	ID         string                 `json:"id"`
	Type       string                 `json:"type"`
	Value      string                 `json:"value"`
	Source     string                 `json:"source"`
	Confidence float64                `json:"confidence"`
	Timestamp  time.Time              `json:"timestamp"`
	Context    map[string]interface{} `json:"context"`
}

// Missing types for Hunting package
type HuntExecutor struct {
	ID           string                 `json:"id"`
	Name         string                 `json:"name"`
	Type         string                 `json:"type"`
	Status       string                 `json:"status"`
	Capabilities []string               `json:"capabilities"`
	Config       map[string]interface{} `json:"config"`
	LastActive   time.Time              `json:"last_active"`
}

type HuntPlaybook struct {
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

type HuntAutomation struct {
	ID         string                 `json:"id"`
	Name       string                 `json:"name"`
	Type       string                 `json:"type"`
	Triggers   []*AutomationTrigger   `json:"triggers"`
	Actions    []*AutomationAction    `json:"actions"`
	Conditions []*AutomationCondition `json:"conditions"`
	Schedule   *Schedule              `json:"schedule"`
	Enabled    bool                   `json:"enabled"`
	LastRun    time.Time              `json:"last_run"`
}

type AutomationTrigger struct {
	Type       string                 `json:"type"`
	Event      string                 `json:"event"`
	Condition  string                 `json:"condition"`
	Parameters map[string]interface{} `json:"parameters"`
	Enabled    bool                   `json:"enabled"`
}

type AutomationAction struct {
	Type       string                 `json:"type"`
	Target     string                 `json:"target"`
	Parameters map[string]interface{} `json:"parameters"`
	Timeout    time.Duration          `json:"timeout"`
	Retries    int                    `json:"retries"`
}

type AutomationCondition struct {
	Field     string      `json:"field"`
	Operator  string      `json:"operator"`
	Value     interface{} `json:"value"`
	LogicalOp string      `json:"logical_op"`
}

type Schedule struct {
	Type       string     `json:"type"`
	Expression string     `json:"expression"`
	Timezone   string     `json:"timezone"`
	StartTime  time.Time  `json:"start_time"`
	EndTime    *time.Time `json:"end_time"`
	Enabled    bool       `json:"enabled"`
}

type SuccessMetric struct {
	Name       string    `json:"name"`
	Type       string    `json:"type"`
	Target     float64   `json:"target"`
	Current    float64   `json:"current"`
	Unit       string    `json:"unit"`
	Trend      string    `json:"trend"`
	LastUpdate time.Time `json:"last_update"`
}

type KillChainMapping struct {
	Phase           string   `json:"phase"`
	Techniques      []string `json:"techniques"`
	Indicators      []string `json:"indicators"`
	Countermeasures []string `json:"countermeasures"`
	Confidence      float64  `json:"confidence"`
}

type AdversaryEmulation struct {
	ID        string               `json:"id"`
	Name      string               `json:"name"`
	Profile   *AdversaryProfile    `json:"profile"`
	Scenarios []*EmulationScenario `json:"scenarios"`
	Tools     []string             `json:"tools"`
	Status    string               `json:"status"`
	LastRun   time.Time            `json:"last_run"`
}

type AdversaryProfile struct {
	Name         string   `json:"name"`
	Group        string   `json:"group"`
	Motivation   []string `json:"motivation"`
	Capabilities []string `json:"capabilities"`
	TTPs         []*TTP   `json:"ttps"`
	Geography    []string `json:"geography"`
}

type EmulationScenario struct {
	ID          string           `json:"id"`
	Name        string           `json:"name"`
	Description string           `json:"description"`
	Phases      []*ScenarioPhase `json:"phases"`
	Objectives  []string         `json:"objectives"`
	Duration    time.Duration    `json:"duration"`
}

type ScenarioPhase struct {
	Phase      string         `json:"phase"`
	Techniques []string       `json:"techniques"`
	Tools      []string       `json:"tools"`
	Duration   time.Duration  `json:"duration"`
	Success    *SuccessMetric `json:"success"`
}

type RedTeamScenario struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Type      string    `json:"type"`
	Objective string    `json:"objective"`
	Target    *Target   `json:"target"`
	Tactics   []string  `json:"tactics"`
	Tools     []string  `json:"tools"`
	Timeline  *Timeline `json:"timeline"`
	Status    string    `json:"status"`
}

type Target struct {
	Type        string   `json:"type"`
	Name        string   `json:"name"`
	IP          string   `json:"ip"`
	Domain      string   `json:"domain"`
	Services    []string `json:"services"`
	Criticality string   `json:"criticality"`
}

type Timeline struct {
	StartTime  time.Time        `json:"start_time"`
	EndTime    time.Time        `json:"end_time"`
	Phases     []*TimelinePhase `json:"phases"`
	Milestones []*Milestone     `json:"milestones"`
}

type TimelinePhase struct {
	Name       string    `json:"name"`
	StartTime  time.Time `json:"start_time"`
	EndTime    time.Time `json:"end_time"`
	Activities []string  `json:"activities"`
	Status     string    `json:"status"`
}

type Milestone struct {
	Name        string    `json:"name"`
	Time        time.Time `json:"time"`
	Status      string    `json:"status"`
	Description string    `json:"description"`
}

type ThreatIntelligenceReq struct {
	Type      string    `json:"type"`
	Priority  string    `json:"priority"`
	Subject   string    `json:"subject"`
	Context   string    `json:"context"`
	Sources   []string  `json:"sources"`
	Deadline  time.Time `json:"deadline"`
	Requestor string    `json:"requestor"`
	Status    string    `json:"status"`
}

type CollaborationModel struct {
	Type          string                 `json:"type"`
	Members       []*TeamMember          `json:"members"`
	Roles         map[string][]string    `json:"roles"`
	Permissions   map[string][]string    `json:"permissions"`
	Communication *CommunicationSettings `json:"communication"`
}

type TeamMember struct {
	ID           string       `json:"id"`
	Name         string       `json:"name"`
	Role         string       `json:"role"`
	Skills       []string     `json:"skills"`
	Availability string       `json:"availability"`
	Contact      *ContactInfo `json:"contact"`
}

type ContactInfo struct {
	Email    string `json:"email"`
	Phone    string `json:"phone"`
	Slack    string `json:"slack"`
	Timezone string `json:"timezone"`
}

type CommunicationSettings struct {
	Channels      []string              `json:"channels"`
	Frequency     string                `json:"frequency"`
	Escalation    *EscalationPolicy     `json:"escalation"`
	Notifications *NotificationSettings `json:"notifications"`
}

type EscalationPolicy struct {
	Levels       []*EscalationLevel `json:"levels"`
	Timeout      time.Duration      `json:"timeout"`
	AutoEscalate bool               `json:"auto_escalate"`
}

type EscalationLevel struct {
	Level      int           `json:"level"`
	Recipients []string      `json:"recipients"`
	Timeout    time.Duration `json:"timeout"`
	Actions    []string      `json:"actions"`
}

type NotificationSettings struct {
	Email   bool                `json:"email"`
	SMS     bool                `json:"sms"`
	Slack   bool                `json:"slack"`
	Push    bool                `json:"push"`
	Urgency map[string][]string `json:"urgency"`
}

type QualityAssurance struct {
	Reviews    []*QAReview            `json:"reviews"`
	Checklist  []*QAItem              `json:"checklist"`
	Standards  map[string]interface{} `json:"standards"`
	Metrics    *QAMetrics             `json:"metrics"`
	LastReview time.Time              `json:"last_review"`
}

type QAReview struct {
	ID       string       `json:"id"`
	Type     string       `json:"type"`
	Subject  string       `json:"subject"`
	Reviewer string       `json:"reviewer"`
	Status   string       `json:"status"`
	Findings []*QAFinding `json:"findings"`
	Score    float64      `json:"score"`
	Date     time.Time    `json:"date"`
}

type QAFinding struct {
	Type           string `json:"type"`
	Severity       string `json:"severity"`
	Description    string `json:"description"`
	Recommendation string `json:"recommendation"`
	Status         string `json:"status"`
}

type QAItem struct {
	ID       string  `json:"id"`
	Category string  `json:"category"`
	Item     string  `json:"item"`
	Required bool    `json:"required"`
	Weight   float64 `json:"weight"`
	Status   string  `json:"status"`
}

type QAMetrics struct {
	PassRate       float64   `json:"pass_rate"`
	AverageScore   float64   `json:"average_score"`
	DefectRate     float64   `json:"defect_rate"`
	CoverageRate   float64   `json:"coverage_rate"`
	LastCalculated time.Time `json:"last_calculated"`
}

// Missing types for Dashboard package
type DataAggregator struct {
	Functions map[string]*AggregateFunction `json:"functions"`
	Window    *TimeWindow                   `json:"window"`
	Grouping  []string                      `json:"grouping"`
	Output    *AggregateOutput              `json:"output"`
}

type AggregateFunction struct {
	Name       string                 `json:"name"`
	Type       string                 `json:"type"`
	Field      string                 `json:"field"`
	Parameters map[string]interface{} `json:"parameters"`
}

type TimeWindow struct {
	Size      time.Duration `json:"size"`
	Slide     time.Duration `json:"slide"`
	Type      string        `json:"type"`
	Alignment string        `json:"alignment"`
}

type AggregateOutput struct {
	Format      string        `json:"format"`
	Destination string        `json:"destination"`
	Frequency   time.Duration `json:"frequency"`
	Retention   time.Duration `json:"retention"`
}

type MetricCalculator struct {
	Metrics    []*MetricDefinition `json:"metrics"`
	Calculator *Calculator         `json:"calculator"`
	Cache      *MetricCache        `json:"cache"`
	Schedule   *Schedule           `json:"schedule"`
}

type MetricDefinition struct {
	Name        string   `json:"name"`
	Type        string   `json:"type"`
	Formula     string   `json:"formula"`
	Unit        string   `json:"unit"`
	Description string   `json:"description"`
	Tags        []string `json:"tags"`
}

type Calculator struct {
	Engine    string                 `json:"engine"`
	Functions map[string]interface{} `json:"functions"`
	Variables map[string]interface{} `json:"variables"`
	Precision int                    `json:"precision"`
}

type MetricCache struct {
	Values  map[string]*MetricValue `json:"values"`
	TTL     time.Duration           `json:"ttl"`
	MaxSize int                     `json:"max_size"`
	HitRate float64                 `json:"hit_rate"`
}

type MetricValue struct {
	Value     interface{} `json:"value"`
	Timestamp time.Time   `json:"timestamp"`
	Quality   string      `json:"quality"`
	Source    string      `json:"source"`
}

type FilterEngine struct {
	Filters     []*Filter          `json:"filters"`
	Rules       []*FilterRule      `json:"rules"`
	Engine      string             `json:"engine"`
	Performance *FilterPerformance `json:"performance"`
}

type Filter struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Type       string `json:"type"`
	Expression string `json:"expression"`
	Enabled    bool   `json:"enabled"`
	Priority   int    `json:"priority"`
}

type FilterRule struct {
	Field    string      `json:"field"`
	Operator string      `json:"operator"`
	Value    interface{} `json:"value"`
	Action   string      `json:"action"`
	Weight   float64     `json:"weight"`
}

type FilterPerformance struct {
	ProcessedCount uint64        `json:"processed_count"`
	FilteredCount  uint64        `json:"filtered_count"`
	AverageLatency time.Duration `json:"average_latency"`
	Throughput     float64       `json:"throughput"`
}

type TransformationEngine struct {
	Transformations []*Transformation     `json:"transformations"`
	Pipeline        *TransformPipeline    `json:"pipeline"`
	Schema          *TransformSchema      `json:"schema"`
	Performance     *TransformPerformance `json:"performance"`
}

type Transformation struct {
	ID         string                 `json:"id"`
	Name       string                 `json:"name"`
	Type       string                 `json:"type"`
	Input      string                 `json:"input"`
	Output     string                 `json:"output"`
	Function   string                 `json:"function"`
	Parameters map[string]interface{} `json:"parameters"`
}

type TransformPipeline struct {
	Stages      []*TransformStage `json:"stages"`
	Parallel    bool              `json:"parallel"`
	ErrorPolicy string            `json:"error_policy"`
	Timeout     time.Duration     `json:"timeout"`
}

type TransformStage struct {
	ID           string          `json:"id"`
	Name         string          `json:"name"`
	Transform    *Transformation `json:"transform"`
	Dependencies []string        `json:"dependencies"`
	Condition    string          `json:"condition"`
}

type TransformSchema struct {
	InputSchema   map[string]interface{} `json:"input_schema"`
	OutputSchema  map[string]interface{} `json:"output_schema"`
	Validation    bool                   `json:"validation"`
	ErrorHandling string                 `json:"error_handling"`
}

type TransformPerformance struct {
	TransformedCount uint64        `json:"transformed_count"`
	ErrorCount       uint64        `json:"error_count"`
	AverageLatency   time.Duration `json:"average_latency"`
	Throughput       float64       `json:"throughput"`
}

type BufferManager struct {
	Buffers map[string]*Buffer `json:"buffers"`
	Policy  *BufferPolicy      `json:"policy"`
	Monitor *BufferMonitor     `json:"monitor"`
	Stats   *BufferStats       `json:"stats"`
}

type Buffer struct {
	ID         string            `json:"id"`
	Type       string            `json:"type"`
	Size       int               `json:"size"`
	MaxSize    int               `json:"max_size"`
	Items      []interface{}     `json:"items"`
	Watermarks *BufferWatermarks `json:"watermarks"`
}

type BufferPolicy struct {
	OverflowPolicy    string `json:"overflow_policy"`
	EvictionPolicy    string `json:"eviction_policy"`
	CompressionPolicy string `json:"compression_policy"`
	PersistencePolicy string `json:"persistence_policy"`
}

type BufferWatermarks struct {
	Low      int `json:"low"`
	High     int `json:"high"`
	Critical int `json:"critical"`
}

type BufferMonitor struct {
	Enabled  bool           `json:"enabled"`
	Interval time.Duration  `json:"interval"`
	Alerts   []*BufferAlert `json:"alerts"`
	Metrics  []string       `json:"metrics"`
}

type BufferAlert struct {
	Type      string  `json:"type"`
	Condition string  `json:"condition"`
	Threshold float64 `json:"threshold"`
	Action    string  `json:"action"`
	Enabled   bool    `json:"enabled"`
}

type BufferStats struct {
	TotalWrites    uint64        `json:"total_writes"`
	TotalReads     uint64        `json:"total_reads"`
	Overflows      uint64        `json:"overflows"`
	Evictions      uint64        `json:"evictions"`
	AverageLatency time.Duration `json:"average_latency"`
	Utilization    float64       `json:"utilization"`
}

type CompressionEngine struct {
	Algorithm  string             `json:"algorithm"`
	Level      int                `json:"level"`
	Dictionary []byte             `json:"dictionary"`
	Stats      *CompressionStats  `json:"stats"`
	Config     *CompressionConfig `json:"config"`
}

type CompressionStats struct {
	CompressedBytes   uint64        `json:"compressed_bytes"`
	UncompressedBytes uint64        `json:"uncompressed_bytes"`
	CompressionRatio  float64       `json:"compression_ratio"`
	AverageLatency    time.Duration `json:"average_latency"`
	Throughput        float64       `json:"throughput"`
}

type CompressionConfig struct {
	BlockSize      int           `json:"block_size"`
	WindowSize     int           `json:"window_size"`
	MinCompression float64       `json:"min_compression"`
	MaxLatency     time.Duration `json:"max_latency"`
}

type TimeSeriesAnalyzer struct {
	Models     []*TimeSeriesModel  `json:"models"`
	Algorithms []string            `json:"algorithms"`
	Features   *TimeSeriesFeatures `json:"features"`
	Forecaster *Forecaster         `json:"forecaster"`
}

type TimeSeriesFeatures struct {
	Trend       bool     `json:"trend"`
	Seasonality bool     `json:"seasonality"`
	Noise       bool     `json:"noise"`
	Outliers    bool     `json:"outliers"`
	Patterns    []string `json:"patterns"`
}

type Forecaster struct {
	Algorithm  string                 `json:"algorithm"`
	Horizon    int                    `json:"horizon"`
	Confidence float64                `json:"confidence"`
	Model      Model                  `json:"model"`
	Parameters map[string]interface{} `json:"parameters"`
}

type StatisticalAnalyzer struct {
	Statistics   []*StatisticDefinition `json:"statistics"`
	Tests        []*StatisticalTest     `json:"tests"`
	Distribution *DistributionAnalyzer  `json:"distribution"`
	Correlation  *CorrelationAnalyzer   `json:"correlation"`
}

type StatisticDefinition struct {
	Name        string                 `json:"name"`
	Type        string                 `json:"type"`
	Function    string                 `json:"function"`
	Parameters  map[string]interface{} `json:"parameters"`
	Description string                 `json:"description"`
}

type StatisticalTest struct {
	Name         string      `json:"name"`
	Type         string      `json:"type"`
	Hypothesis   string      `json:"hypothesis"`
	Significance float64     `json:"significance"`
	Result       *TestResult `json:"result"`
}

type TestResult struct {
	Statistic  float64 `json:"statistic"`
	PValue     float64 `json:"p_value"`
	Critical   float64 `json:"critical"`
	Conclusion string  `json:"conclusion"`
	Confidence float64 `json:"confidence"`
}

type DistributionAnalyzer struct {
	Type       string             `json:"type"`
	Parameters map[string]float64 `json:"parameters"`
	Goodness   *GoodnessOfFit     `json:"goodness"`
	Quantiles  map[string]float64 `json:"quantiles"`
}

type GoodnessOfFit struct {
	Test       string  `json:"test"`
	Statistic  float64 `json:"statistic"`
	PValue     float64 `json:"p_value"`
	Hypothesis string  `json:"hypothesis"`
}

type CorrelationAnalyzer struct {
	Method      string      `json:"method"`
	Matrix      [][]float64 `json:"matrix"`
	Threshold   float64     `json:"threshold"`
	Significant []string    `json:"significant"`
}

// Additional hunting types
type EvidenceCollector struct {
	Sources   map[string]*EvidenceSource `json:"sources"`
	Artifacts []*DigitalArtifact         `json:"artifacts"`
	Chain     *EvidenceChain             `json:"chain"`
	Config    map[string]interface{}     `json:"config"`
}

type EvidenceSource struct {
	Type        string    `json:"type"`
	Location    string    `json:"location"`
	Reliability float64   `json:"reliability"`
	LastAccess  time.Time `json:"last_access"`
}

type DigitalArtifact struct {
	ID       string                 `json:"id"`
	Type     string                 `json:"type"`
	Hash     string                 `json:"hash"`
	Size     int64                  `json:"size"`
	Created  time.Time              `json:"created"`
	Metadata map[string]interface{} `json:"metadata"`
}

type EvidenceChain struct {
	Links     []*ChainLink `json:"links"`
	Integrity bool         `json:"integrity"`
	Verified  bool         `json:"verified"`
	Timestamp time.Time    `json:"timestamp"`
}

type ChainLink struct {
	Hash      string    `json:"hash"`
	Previous  string    `json:"previous"`
	Evidence  string    `json:"evidence"`
	Timestamp time.Time `json:"timestamp"`
}

type AttackChainAnalyzer struct {
	Chains    []*AttackChain           `json:"chains"`
	Patterns  map[string]*ChainPattern `json:"patterns"`
	Predictor *ChainPredictor          `json:"predictor"`
	Config    map[string]interface{}   `json:"config"`
}

type AttackChain struct {
	ID         string        `json:"id"`
	Steps      []*AttackStep `json:"steps"`
	Timeline   []time.Time   `json:"timeline"`
	Confidence float64       `json:"confidence"`
	Complete   bool          `json:"complete"`
}

type AttackStep struct {
	Technique string    `json:"technique"`
	Tool      string    `json:"tool"`
	Target    string    `json:"target"`
	Success   bool      `json:"success"`
	Timestamp time.Time `json:"timestamp"`
}

type ChainPattern struct {
	Sequence  []string  `json:"sequence"`
	Frequency int       `json:"frequency"`
	Success   float64   `json:"success"`
	LastSeen  time.Time `json:"last_seen"`
}

type ChainPredictor struct {
	Model       string             `json:"model"`
	Accuracy    float64            `json:"accuracy"`
	Predictions map[string]float64 `json:"predictions"`
	LastTrained time.Time          `json:"last_trained"`
}

type MITRETacticsMapper struct {
	Tactics    map[string]*MITRETactic    `json:"tactics"`
	Techniques map[string]*MITRETechnique `json:"techniques"`
	Procedures map[string]*MITREProcedure `json:"procedures"`
	Mapping    map[string][]string        `json:"mapping"`
}

type MITRETactic struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Techniques  []string `json:"techniques"`
}

type MITRETechnique struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Tactic      string   `json:"tactic"`
	Description string   `json:"description"`
	Procedures  []string `json:"procedures"`
}

type MITREProcedure struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Technique   string   `json:"technique"`
	Description string   `json:"description"`
	Groups      []string `json:"groups"`
}

type TechniqueDetector struct {
	Detectors map[string]*Detector   `json:"detectors"`
	Rules     []*DetectionRule       `json:"rules"`
	Analytics []*TechniqueAnalytic   `json:"analytics"`
	Config    map[string]interface{} `json:"config"`
}

type DetectionRule struct {
	ID        string  `json:"id"`
	Name      string  `json:"name"`
	Logic     string  `json:"logic"`
	Threshold float64 `json:"threshold"`
	Enabled   bool    `json:"enabled"`
}

type TechniqueAnalytic struct {
	ID        string        `json:"id"`
	Technique string        `json:"technique"`
	Query     string        `json:"query"`
	Frequency time.Duration `json:"frequency"`
	LastRun   time.Time     `json:"last_run"`
}

type CampaignTracker struct {
	Campaigns  map[string]*Campaign    `json:"campaigns"`
	Indicators map[string]*CampaignIOC `json:"indicators"`
	Timeline   *CampaignTimeline       `json:"timeline"`
	Config     map[string]interface{}  `json:"config"`
}

type Campaign struct {
	ID     string     `json:"id"`
	Name   string     `json:"name"`
	Group  string     `json:"group"`
	Start  time.Time  `json:"start"`
	End    *time.Time `json:"end"`
	Active bool       `json:"active"`
	IOCs   []string   `json:"iocs"`
}

type CampaignIOC struct {
	Value     string    `json:"value"`
	Type      string    `json:"type"`
	Campaign  string    `json:"campaign"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

type CampaignTimeline struct {
	Events   []*CampaignEvent `json:"events"`
	Phases   []*CampaignPhase `json:"phases"`
	Duration time.Duration    `json:"duration"`
	Updated  time.Time        `json:"updated"`
}

type CampaignEvent struct {
	ID          string    `json:"id"`
	Type        string    `json:"type"`
	Description string    `json:"description"`
	Timestamp   time.Time `json:"timestamp"`
	IOCs        []string  `json:"iocs"`
}

type CampaignPhase struct {
	Name    string     `json:"name"`
	Start   time.Time  `json:"start"`
	End     *time.Time `json:"end"`
	TTPs    []string   `json:"ttps"`
	Success bool       `json:"success"`
}

type ThreatActorProfiler struct {
	Profiles    map[string]*ThreatActorProfile `json:"profiles"`
	Behaviors   map[string]*ActorBehavior      `json:"behaviors"`
	Attribution *Attribution                   `json:"attribution"`
	Config      map[string]interface{}         `json:"config"`
}

type ThreatActorProfile struct {
	ID             string   `json:"id"`
	Name           string   `json:"name"`
	Aliases        []string `json:"aliases"`
	Country        string   `json:"country"`
	Motivation     string   `json:"motivation"`
	Sophistication string   `json:"sophistication"`
	TTPs           []string `json:"ttps"`
	Campaigns      []string `json:"campaigns"`
}

type ActorBehavior struct {
	Pattern    string    `json:"pattern"`
	Frequency  float64   `json:"frequency"`
	Confidence float64   `json:"confidence"`
	Examples   []string  `json:"examples"`
	LastSeen   time.Time `json:"last_seen"`
}

type Attribution struct {
	Confidence float64            `json:"confidence"`
	Factors    map[string]float64 `json:"factors"`
	Evidence   []string           `json:"evidence"`
	Analysis   string             `json:"analysis"`
	Updated    time.Time          `json:"updated"`
}

type IOCManager struct {
	IOCs       map[string]*IOC        `json:"iocs"`
	Sources    []*IOCSource           `json:"sources"`
	Enrichment *IOCEnrichment         `json:"enrichment"`
	Analytics  *IOCAnalyzer           `json:"analytics"`
	Config     map[string]interface{} `json:"config"`
}

type IOCSource struct {
	Name        string    `json:"name"`
	URL         string    `json:"url"`
	Type        string    `json:"type"`
	Reliability float64   `json:"reliability"`
	LastUpdate  time.Time `json:"last_update"`
}

type IOCAnalyzer struct {
	Patterns     map[string]*IOCPattern `json:"patterns"`
	Correlations []*IOCCorrelation      `json:"correlations"`
	Stats        *IOCStatistics         `json:"stats"`
	Config       map[string]interface{} `json:"config"`
}

type IOCCorrelation struct {
	IOC1     string    `json:"ioc1"`
	IOC2     string    `json:"ioc2"`
	Type     string    `json:"type"`
	Strength float64   `json:"strength"`
	LastSeen time.Time `json:"last_seen"`
}

type IOCStatistics struct {
	Total    int            `json:"total"`
	ByType   map[string]int `json:"by_type"`
	BySource map[string]int `json:"by_source"`
	Recent   int            `json:"recent"`
	Updated  time.Time      `json:"updated"`
}

// Dashboard analyzer types
type TrendAnalyzer struct {
	Trends     map[string]*Trend      `json:"trends"`
	Forecasts  map[string]*Forecast   `json:"forecasts"`
	Algorithms []string               `json:"algorithms"`
	Config     map[string]interface{} `json:"config"`
}

type Trend struct {
	Metric     string        `json:"metric"`
	Direction  string        `json:"direction"`
	Strength   float64       `json:"strength"`
	Duration   time.Duration `json:"duration"`
	Confidence float64       `json:"confidence"`
}

type Forecast struct {
	Metric     string      `json:"metric"`
	Values     []float64   `json:"values"`
	Timestamps []time.Time `json:"timestamps"`
	Confidence []float64   `json:"confidence"`
	Method     string      `json:"method"`
}

type PatternRecognition struct {
	Patterns map[string]*Pattern    `json:"patterns"`
	Matcher  *PatternMatcher        `json:"matcher"`
	Learner  *PatternLearner        `json:"learner"`
	Config   map[string]interface{} `json:"config"`
}

type Pattern struct {
	ID        string    `json:"id"`
	Type      string    `json:"type"`
	Signature []float64 `json:"signature"`
	Frequency int       `json:"frequency"`
	LastSeen  time.Time `json:"last_seen"`
}

type PatternMatcher struct {
	Algorithm string          `json:"algorithm"`
	Threshold float64         `json:"threshold"`
	Cache     map[string]bool `json:"cache"`
	Stats     *MatchingStats  `json:"stats"`
}

type PatternLearner struct {
	Model       string    `json:"model"`
	Training    bool      `json:"training"`
	Accuracy    float64   `json:"accuracy"`
	LastTrained time.Time `json:"last_trained"`
}

type MatchingStats struct {
	Matches  int     `json:"matches"`
	FalsePos int     `json:"false_positives"`
	FalseNeg int     `json:"false_negatives"`
	Accuracy float64 `json:"accuracy"`
}

type BehaviorAnalyzer struct {
	Profiles  map[string]*BehaviorProfile `json:"profiles"`
	Anomalies []*BehaviorAnomaly          `json:"anomalies"`
	Baselines map[string]*Baseline        `json:"baselines"`
	Config    map[string]interface{}      `json:"config"`
}

type BehaviorProfile struct {
	UserID     string             `json:"user_id"`
	Patterns   map[string]float64 `json:"patterns"`
	LastUpdate time.Time          `json:"last_update"`
	Confidence float64            `json:"confidence"`
}

type BehaviorAnomaly struct {
	UserID    string                 `json:"user_id"`
	Type      string                 `json:"type"`
	Severity  float64                `json:"severity"`
	Timestamp time.Time              `json:"timestamp"`
	Details   map[string]interface{} `json:"details"`
}

type Baseline struct {
	Metric  string    `json:"metric"`
	Mean    float64   `json:"mean"`
	StdDev  float64   `json:"std_dev"`
	Min     float64   `json:"min"`
	Max     float64   `json:"max"`
	Updated time.Time `json:"updated"`
}

type NetworkAnalyzer struct {
	Flows     []*NetworkFlow         `json:"flows"`
	Topology  *NetworkTopology       `json:"topology"`
	Anomalies []*NetworkAnomaly      `json:"anomalies"`
	Config    map[string]interface{} `json:"config"`
}

type NetworkFlow struct {
	SourceIP   string        `json:"source_ip"`
	DestIP     string        `json:"dest_ip"`
	SourcePort int           `json:"source_port"`
	DestPort   int           `json:"dest_port"`
	Protocol   string        `json:"protocol"`
	Bytes      int64         `json:"bytes"`
	Packets    int64         `json:"packets"`
	Duration   time.Duration `json:"duration"`
}

type NetworkTopology struct {
	Nodes   []*NetworkNode `json:"nodes"`
	Edges   []*NetworkEdge `json:"edges"`
	Subnets []*Subnet      `json:"subnets"`
	Updated time.Time      `json:"updated"`
}

type NetworkNode struct {
	IP       string    `json:"ip"`
	Type     string    `json:"type"`
	Role     string    `json:"role"`
	Services []string  `json:"services"`
	LastSeen time.Time `json:"last_seen"`
}

type NetworkEdge struct {
	Source string  `json:"source"`
	Dest   string  `json:"dest"`
	Weight float64 `json:"weight"`
	Type   string  `json:"type"`
}

type Subnet struct {
	CIDR  string   `json:"cidr"`
	Name  string   `json:"name"`
	Type  string   `json:"type"`
	Nodes []string `json:"nodes"`
}

type NetworkAnomaly struct {
	Type      string    `json:"type"`
	Source    string    `json:"source"`
	Dest      string    `json:"dest"`
	Severity  float64   `json:"severity"`
	Timestamp time.Time `json:"timestamp"`
	Details   string    `json:"details"`
}

type UserAnalyzer struct {
	Users      map[string]*UserProfile `json:"users"`
	Sessions   map[string]*UserSession `json:"sessions"`
	Activities []*UserActivity         `json:"activities"`
	Config     map[string]interface{}  `json:"config"`
}

type UserProfile struct {
	ID          string    `json:"id"`
	Username    string    `json:"username"`
	Role        string    `json:"role"`
	LastLogin   time.Time `json:"last_login"`
	Permissions []string  `json:"permissions"`
	Risk        float64   `json:"risk"`
}

type UserActivity struct {
	UserID    string    `json:"user_id"`
	Action    string    `json:"action"`
	Resource  string    `json:"resource"`
	Result    string    `json:"result"`
	Timestamp time.Time `json:"timestamp"`
	IP        string    `json:"ip"`
}

type AssetAnalyzer struct {
	Assets    map[string]*Asset      `json:"assets"`
	Inventory *AssetInventory        `json:"inventory"`
	Risks     []*AssetRisk           `json:"risks"`
	Config    map[string]interface{} `json:"config"`
}

type Asset struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Type        string    `json:"type"`
	Owner       string    `json:"owner"`
	Value       string    `json:"value"`
	Location    string    `json:"location"`
	LastScanned time.Time `json:"last_scanned"`
}

type AssetInventory struct {
	Total      int            `json:"total"`
	ByType     map[string]int `json:"by_type"`
	ByOwner    map[string]int `json:"by_owner"`
	ByLocation map[string]int `json:"by_location"`
	Updated    time.Time      `json:"updated"`
}

type AssetRisk struct {
	AssetID     string    `json:"asset_id"`
	Type        string    `json:"type"`
	Severity    string    `json:"severity"`
	Score       float64   `json:"score"`
	Description string    `json:"description"`
	Timestamp   time.Time `json:"timestamp"`
}

type ThreatAnalyzer struct {
	Threats      map[string]*ThreatInfo `json:"threats"`
	Intelligence *ThreatIntelligence    `json:"intelligence"`
	Predictions  []*ThreatPrediction    `json:"predictions"`
	Config       map[string]interface{} `json:"config"`
}

type ThreatInfo struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Type        string   `json:"type"`
	Severity    string   `json:"severity"`
	Description string   `json:"description"`
	TTPs        []string `json:"ttps"`
	IOCs        []string `json:"iocs"`
}

type ThreatPrediction struct {
	ThreatID    string        `json:"threat_id"`
	Probability float64       `json:"probability"`
	Timeframe   time.Duration `json:"timeframe"`
	Confidence  float64       `json:"confidence"`
	Factors     []string      `json:"factors"`
}

type ComplianceAnalyzer struct {
	Frameworks  map[string]*ComplianceFramework `json:"frameworks"`
	Controls    map[string]*Control             `json:"controls"`
	Assessments []*ComplianceAssessment         `json:"assessments"`
	Config      map[string]interface{}          `json:"config"`
}

type ComplianceFramework struct {
	ID       string    `json:"id"`
	Name     string    `json:"name"`
	Version  string    `json:"version"`
	Controls []string  `json:"controls"`
	Updated  time.Time `json:"updated"`
}

type Control struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Category    string    `json:"category"`
	Status      string    `json:"status"`
	LastTest    time.Time `json:"last_test"`
}

type ComplianceAssessment struct {
	FrameworkID string            `json:"framework_id"`
	Score       float64           `json:"score"`
	Passed      int               `json:"passed"`
	Failed      int               `json:"failed"`
	Timestamp   time.Time         `json:"timestamp"`
	Details     map[string]string `json:"details"`
}

type BusinessImpactAnalyzer struct {
	Impacts   []*BusinessImpact      `json:"impacts"`
	Metrics   *ImpactMetrics         `json:"metrics"`
	Scenarios []*ImpactScenario      `json:"scenarios"`
	Config    map[string]interface{} `json:"config"`
}

type BusinessImpact struct {
	ID           string    `json:"id"`
	Type         string    `json:"type"`
	Asset        string    `json:"asset"`
	Financial    float64   `json:"financial"`
	Operational  string    `json:"operational"`
	Reputational string    `json:"reputational"`
	Timestamp    time.Time `json:"timestamp"`
}

type ImpactMetrics struct {
	TotalFinancial   float64       `json:"total_financial"`
	AvgDowntime      time.Duration `json:"avg_downtime"`
	AffectedServices int           `json:"affected_services"`
	CustomerImpact   float64       `json:"customer_impact"`
	Updated          time.Time     `json:"updated"`
}

type ImpactScenario struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Likelihood float64  `json:"likelihood"`
	Impact     float64  `json:"impact"`
	Risk       float64  `json:"risk"`
	Mitigation []string `json:"mitigation"`
}

type ChartRenderer struct {
	Charts    map[string]*Chart         `json:"charts"`
	Templates map[string]*ChartTemplate `json:"templates"`
	Config    map[string]interface{}    `json:"config"`
}

type Chart struct {
	ID      string                 `json:"id"`
	Type    string                 `json:"type"`
	Title   string                 `json:"title"`
	Data    interface{}            `json:"data"`
	Options map[string]interface{} `json:"options"`
	Updated time.Time              `json:"updated"`
}

type ChartTemplate struct {
	ID             string                 `json:"id"`
	Name           string                 `json:"name"`
	Type           string                 `json:"type"`
	Layout         map[string]interface{} `json:"layout"`
	DefaultOptions map[string]interface{} `json:"default_options"`
}

// Additional hunting types
type ReportingEngine struct {
	Reports   map[string]*Report         `json:"reports"`
	Templates map[string]*ReportTemplate `json:"templates"`
	Scheduler *ReportScheduler           `json:"scheduler"`
	Exporter  *ReportExporter            `json:"exporter"`
}

type ThreatHunt struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Hypothesis string     `json:"hypothesis"`
	Status     string     `json:"status"`
	Priority   string     `json:"priority"`
	Hunter     string     `json:"hunter"`
	StartTime  time.Time  `json:"start_time"`
	EndTime    *time.Time `json:"end_time"`
	Results    []string   `json:"results"`
}

type ThreatInvestigation struct {
	ID       string      `json:"id"`
	HuntID   string      `json:"hunt_id"`
	Findings []string    `json:"findings"`
	Evidence []string    `json:"evidence"`
	Status   string      `json:"status"`
	Analyst  string      `json:"analyst"`
	Timeline []time.Time `json:"timeline"`
}

type ThreatHuntingStats struct {
	ActiveHunts    int           `json:"active_hunts"`
	CompletedHunts int           `json:"completed_hunts"`
	TotalFindings  int           `json:"total_findings"`
	AverageTime    time.Duration `json:"average_time"`
}

type MLHuntingEngine struct {
	Models     map[string]*HuntingModel `json:"models"`
	Predictors []*ThreatPredictor       `json:"predictors"`
	Analytics  *HuntingAnalytics        `json:"analytics"`
	Config     map[string]interface{}   `json:"config"`
}

type AIHuntingAssistant struct {
	NLP         *NLPProcessor     `json:"nlp"`
	Recommender *HuntRecommender  `json:"recommender"`
	AutoHunter  *AutomatedHunter  `json:"auto_hunter"`
	Knowledge   *HuntingKnowledge `json:"knowledge"`
}

type HuntStrategy struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Type    string   `json:"type"`
	Steps   []string `json:"steps"`
	Tools   []string `json:"tools"`
	Tactics []string `json:"tactics"`
}

type IOCScoring struct {
	Algorithm  string                 `json:"algorithm"`
	Weights    map[string]float64     `json:"weights"`
	Thresholds map[string]float64     `json:"thresholds"`
	Config     map[string]interface{} `json:"config"`
}

type IOCLifecycle struct {
	Created  time.Time   `json:"created"`
	LastSeen time.Time   `json:"last_seen"`
	Expiry   *time.Time  `json:"expiry"`
	Status   string      `json:"status"`
	Updates  []time.Time `json:"updates"`
}

type CustomIndicatorEngine struct {
	Indicators map[string]*CustomIndicator `json:"indicators"`
	Rules      []*IndicatorRule            `json:"rules"`
	Matcher    *IndicatorMatcher           `json:"matcher"`
	Config     map[string]interface{}      `json:"config"`
}

type IndicatorMatcher struct {
	Algorithm string                 `json:"algorithm"`
	Patterns  map[string]string      `json:"patterns"`
	Threshold float64                `json:"threshold"`
	Config    map[string]interface{} `json:"config"`
}

// Dashboard types
type DashboardConfig struct {
	Layout  string                 `json:"layout"`
	Widgets []string               `json:"widgets"`
	Refresh time.Duration          `json:"refresh"`
	Theme   string                 `json:"theme"`
	Options map[string]interface{} `json:"options"`
}

type UserPreferences struct {
	UserID    string            `json:"user_id"`
	Dashboard *DashboardConfig  `json:"dashboard"`
	Alerts    map[string]bool   `json:"alerts"`
	Filters   map[string]string `json:"filters"`
	Language  string            `json:"language"`
}

type DataStream struct {
	ID     string  `json:"id"`
	Type   string  `json:"type"`
	Source string  `json:"source"`
	Format string  `json:"format"`
	Active bool    `json:"active"`
	Rate   float64 `json:"rate"`
}

type DashboardStats struct {
	ActiveUsers  int           `json:"active_users"`
	TotalWidgets int           `json:"total_widgets"`
	DataSources  int           `json:"data_sources"`
	ResponseTime time.Duration `json:"response_time"`
}

type AIInsightsEngine struct {
	Models     []*InsightModel     `json:"models"`
	Generators []*InsightGenerator `json:"generators"`
	Correlator *InsightCorrelator  `json:"correlator"`
	Presenter  *InsightPresenter   `json:"presenter"`
}

type PredictiveAnalytics struct {
	Predictors []*ThreatPredictor `json:"predictors"`
	Forecasts  []*ThreatForecast  `json:"forecasts"`
	Models     []*PredictiveModel `json:"models"`
	Accuracy   float64            `json:"accuracy"`
}

type AnomalyDetectionEngine struct {
	Detectors []*AnomalyDetector     `json:"detectors"`
	Baselines []*AnomalyBaseline     `json:"baselines"`
	Alerts    []*AnomalyAlert        `json:"alerts"`
	Config    map[string]interface{} `json:"config"`
}

type CustomizationEngine struct {
	Templates map[string]*DashboardTemplate `json:"templates"`
	Themes    map[string]*DashboardTheme    `json:"themes"`
	Widgets   map[string]*CustomWidget      `json:"widgets"`
	Builder   *DashboardBuilder             `json:"builder"`
}

type IntegrationHub struct {
	Connectors map[string]*DataConnector `json:"connectors"`
	APIs       map[string]*APIConnector  `json:"apis"`
	Webhooks   []*WebhookConnector       `json:"webhooks"`
	Config     map[string]interface{}    `json:"config"`
}

// Additional missing hunting types
type ReportExporter struct {
	Formats      []string               `json:"formats"`
	Templates    map[string]string      `json:"templates"`
	Destinations []string               `json:"destinations"`
	Config       map[string]interface{} `json:"config"`
}

type HuntingModel struct {
	ID        string   `json:"id"`
	Type      string   `json:"type"`
	Algorithm string   `json:"algorithm"`
	Features  []string `json:"features"`
	Accuracy  float64  `json:"accuracy"`
	Trained   bool     `json:"trained"`
}

type ThreatPredictor struct {
	Model      *HuntingModel `json:"model"`
	Horizon    time.Duration `json:"horizon"`
	Confidence float64       `json:"confidence"`
	Features   []string      `json:"features"`
	Active     bool          `json:"active"`
}

type HuntingAnalytics struct {
	Models      []*HuntingModel     `json:"models"`
	Metrics     map[string]float64  `json:"metrics"`
	Trends      []*TrendAnalysis    `json:"trends"`
	Predictions []*ThreatPrediction `json:"predictions"`
}

type HuntRecommender struct {
	Algorithm string                `json:"algorithm"`
	Model     *HuntingModel         `json:"model"`
	Rules     []*RecommendationRule `json:"rules"`
	History   []*HuntRecommendation `json:"history"`
}

type AutomatedHunter struct {
	Strategies []*HuntStrategy `json:"strategies"`
	Scheduler  *HuntScheduler  `json:"scheduler"`
	Executor   *HuntExecutor   `json:"executor"`
	Monitor    *HuntMonitor    `json:"monitor"`
}

type HuntingKnowledge struct {
	TTPs      map[string]*TTPKnowledge      `json:"ttps"`
	IOCs      map[string]*IOCKnowledge      `json:"iocs"`
	Actors    map[string]*ActorKnowledge    `json:"actors"`
	Campaigns map[string]*CampaignKnowledge `json:"campaigns"`
}

type CustomIndicator struct {
	ID        string    `json:"id"`
	Type      string    `json:"type"`
	Pattern   string    `json:"pattern"`
	Logic     string    `json:"logic"`
	Threshold float64   `json:"threshold"`
	Active    bool      `json:"active"`
	Created   time.Time `json:"created"`
}

// Final missing hunting support types
type IndicatorRule struct {
	ID       string `json:"id"`
	Pattern  string `json:"pattern"`
	Logic    string `json:"logic"`
	Action   string `json:"action"`
	Priority int    `json:"priority"`
	Active   bool   `json:"active"`
}

type TrendAnalysis struct {
	Metric     string        `json:"metric"`
	Direction  string        `json:"direction"`
	Magnitude  float64       `json:"magnitude"`
	Confidence float64       `json:"confidence"`
	Timeframe  time.Duration `json:"timeframe"`
}

type RecommendationRule struct {
	ID        string  `json:"id"`
	Condition string  `json:"condition"`
	Action    string  `json:"action"`
	Priority  int     `json:"priority"`
	Score     float64 `json:"score"`
}

type HuntRecommendation struct {
	ID          string    `json:"id"`
	Type        string    `json:"type"`
	Description string    `json:"description"`
	Priority    string    `json:"priority"`
	Confidence  float64   `json:"confidence"`
	Created     time.Time `json:"created"`
}

type HuntScheduler struct {
	Schedule string                 `json:"schedule"`
	Queue    []string               `json:"queue"`
	Active   bool                   `json:"active"`
	Config   map[string]interface{} `json:"config"`
}

type HuntMonitor struct {
	Status  string             `json:"status"`
	Metrics map[string]float64 `json:"metrics"`
	Alerts  []string           `json:"alerts"`
	History []time.Time        `json:"history"`
}

type TTPKnowledge struct {
	ID          string `json:"id"`
	Tactic      string `json:"tactic"`
	Technique   string `json:"technique"`
	Procedure   string `json:"procedure"`
	MITRE       string `json:"mitre"`
	Description string `json:"description"`
}

type IOCKnowledge struct {
	Type       string   `json:"type"`
	Value      string   `json:"value"`
	Context    string   `json:"context"`
	Sources    []string `json:"sources"`
	Confidence float64  `json:"confidence"`
}

type ActorKnowledge struct {
	Name        string   `json:"name"`
	Aliases     []string `json:"aliases"`
	TTPs        []string `json:"ttps"`
	Targets     []string `json:"targets"`
	Attribution string   `json:"attribution"`
}

type CampaignKnowledge struct {
	Name       string   `json:"name"`
	Objectives []string `json:"objectives"`
	TTPs       []string `json:"ttps"`
	IOCs       []string `json:"iocs"`
	Timeline   string   `json:"timeline"`
}

// Final AI and Dashboard types
type InsightModel struct {
	Algorithm string                 `json:"algorithm"`
	Features  []string               `json:"features"`
	Accuracy  float64                `json:"accuracy"`
	Trained   bool                   `json:"trained"`
	Config    map[string]interface{} `json:"config"`
}

type InsightGenerator struct {
	Models    []*InsightModel        `json:"models"`
	Rules     []string               `json:"rules"`
	Templates map[string]string      `json:"templates"`
	Config    map[string]interface{} `json:"config"`
}

type InsightCorrelator struct {
	Algorithm string        `json:"algorithm"`
	Rules     []string      `json:"rules"`
	Threshold float64       `json:"threshold"`
	Window    time.Duration `json:"window"`
}

type InsightPresenter struct {
	Formats   []string               `json:"formats"`
	Templates map[string]string      `json:"templates"`
	Filters   []string               `json:"filters"`
	Config    map[string]interface{} `json:"config"`
}

type ThreatForecast struct {
	Type        string        `json:"type"`
	Probability float64       `json:"probability"`
	Timeframe   time.Duration `json:"timeframe"`
	Confidence  float64       `json:"confidence"`
	Description string        `json:"description"`
}

type PredictiveModel struct {
	Algorithm string        `json:"algorithm"`
	Features  []string      `json:"features"`
	Horizon   time.Duration `json:"horizon"`
	Accuracy  float64       `json:"accuracy"`
	Trained   bool          `json:"trained"`
}

type AnomalyBaseline struct {
	Metric  string    `json:"metric"`
	Mean    float64   `json:"mean"`
	StdDev  float64   `json:"std_dev"`
	Min     float64   `json:"min"`
	Max     float64   `json:"max"`
	Updated time.Time `json:"updated"`
}

type AnomalyAlert struct {
	ID        string    `json:"id"`
	Type      string    `json:"type"`
	Severity  string    `json:"severity"`
	Metric    string    `json:"metric"`
	Value     float64   `json:"value"`
	Threshold float64   `json:"threshold"`
	Timestamp time.Time `json:"timestamp"`
}

type DashboardTemplate struct {
	ID      string                 `json:"id"`
	Name    string                 `json:"name"`
	Layout  string                 `json:"layout"`
	Widgets []string               `json:"widgets"`
	Config  map[string]interface{} `json:"config"`
}

type DashboardTheme struct {
	Name   string                 `json:"name"`
	Colors map[string]string      `json:"colors"`
	Fonts  map[string]string      `json:"fonts"`
	Layout map[string]interface{} `json:"layout"`
}

type CustomWidget struct {
	ID         string                 `json:"id"`
	Type       string                 `json:"type"`
	Title      string                 `json:"title"`
	DataSource string                 `json:"data_source"`
	Config     map[string]interface{} `json:"config"`
}

type DashboardBuilder struct {
	Templates []*DashboardTemplate   `json:"templates"`
	Widgets   []*CustomWidget        `json:"widgets"`
	Themes    []*DashboardTheme      `json:"themes"`
	Config    map[string]interface{} `json:"config"`
}

type DataConnector struct {
	Type     string                 `json:"type"`
	Endpoint string                 `json:"endpoint"`
	Auth     map[string]string      `json:"auth"`
	Active   bool                   `json:"active"`
	Config   map[string]interface{} `json:"config"`
}

type APIConnector struct {
	URL     string            `json:"url"`
	Method  string            `json:"method"`
	Headers map[string]string `json:"headers"`
	Auth    map[string]string `json:"auth"`
	Active  bool              `json:"active"`
}

type WebhookConnector struct {
	URL    string                 `json:"url"`
	Secret string                 `json:"secret"`
	Events []string               `json:"events"`
	Active bool                   `json:"active"`
	Config map[string]interface{} `json:"config"`
}

// Missing engine types for various packages
type HuntingEngine struct {
	ID           string                 `json:"id"`
	Name         string                 `json:"name"`
	Type         string                 `json:"type"`
	Status       string                 `json:"status"`
	Config       map[string]interface{} `json:"config"`
	Capabilities []string               `json:"capabilities"`
	LastUpdate   time.Time              `json:"last_update"`
	Performance  *EnginePerformance     `json:"performance"`
}

type IndicatorEngine struct {
	ID         string                 `json:"id"`
	Rules      []*IndicatorRule       `json:"rules"`
	Patterns   map[string]string      `json:"patterns"`
	Matcher    *IndicatorMatcher      `json:"matcher"`
	Stats      *IndicatorStats        `json:"stats"`
	Config     map[string]interface{} `json:"config"`
	LastUpdate time.Time              `json:"last_update"`
}

type CorrelationEngine struct {
	ID          string                 `json:"id"`
	Rules       []*CorrelationRule     `json:"rules"`
	Algorithms  []string               `json:"algorithms"`
	Window      time.Duration          `json:"window"`
	Threshold   float64                `json:"threshold"`
	Stats       *CorrelationStats      `json:"stats"`
	Config      map[string]interface{} `json:"config"`
	Performance *EnginePerformance     `json:"performance"`
}

type WorkflowEngine struct {
	ID          string                 `json:"id"`
	Workflows   map[string]*Workflow   `json:"workflows"`
	Scheduler   *WorkflowScheduler     `json:"scheduler"`
	Executor    *WorkflowExecutor      `json:"executor"`
	Monitor     *WorkflowMonitor       `json:"monitor"`
	Config      map[string]interface{} `json:"config"`
	Performance *EnginePerformance     `json:"performance"`
}

type PlaybookEngine struct {
	ID          string                 `json:"id"`
	Playbooks   map[string]*Playbook   `json:"playbooks"`
	Executor    *PlaybookExecutor      `json:"executor"`
	Scheduler   *PlaybookScheduler     `json:"scheduler"`
	Monitor     *PlaybookMonitor       `json:"monitor"`
	Config      map[string]interface{} `json:"config"`
	Performance *EnginePerformance     `json:"performance"`
}

type ResponseEngine struct {
	ID          string                 `json:"id"`
	Actions     map[string]*Action     `json:"actions"`
	Triggers    []*ResponseTrigger     `json:"triggers"`
	Conditions  []*ResponseCondition   `json:"conditions"`
	Executor    *ResponseExecutor      `json:"executor"`
	Config      map[string]interface{} `json:"config"`
	Performance *EnginePerformance     `json:"performance"`
}

type ReportEngine struct {
	ID          string                 `json:"id"`
	Reports     map[string]*Report     `json:"reports"`
	Templates   map[string]*Template   `json:"templates"`
	Generator   *ReportGenerator       `json:"generator"`
	Scheduler   *ReportScheduler       `json:"scheduler"`
	Config      map[string]interface{} `json:"config"`
	Performance *EnginePerformance     `json:"performance"`
}

type ExecutionEngine struct {
	ID          string                 `json:"id"`
	Jobs        map[string]*Job        `json:"jobs"`
	Queue       *JobQueue              `json:"queue"`
	Executor    *JobExecutor           `json:"executor"`
	Monitor     *JobMonitor            `json:"monitor"`
	Config      map[string]interface{} `json:"config"`
	Performance *EnginePerformance     `json:"performance"`
}

type DashboardEngine struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Type        string                 `json:"type"`
	Status      string                 `json:"status"`
	Config      map[string]interface{} `json:"config"`
	Components  []string               `json:"components"`
	Performance *EnginePerformance     `json:"performance"`
	LastUpdate  time.Time              `json:"last_update"`
}

// Engine support types
type EnginePerformance struct {
	Throughput      float64       `json:"throughput"`
	Latency         time.Duration `json:"latency"`
	ErrorRate       float64       `json:"error_rate"`
	ResourceUsage   float64       `json:"resource_usage"`
	LastMeasurement time.Time     `json:"last_measurement"`
}

type IndicatorStats struct {
	TotalRules     int           `json:"total_rules"`
	ActiveRules    int           `json:"active_rules"`
	MatchCount     uint64        `json:"match_count"`
	ProcessedCount uint64        `json:"processed_count"`
	AverageLatency time.Duration `json:"average_latency"`
	LastUpdate     time.Time     `json:"last_update"`
}

type CorrelationStats struct {
	TotalRules       int           `json:"total_rules"`
	ActiveRules      int           `json:"active_rules"`
	CorrelationCount uint64        `json:"correlation_count"`
	ProcessedEvents  uint64        `json:"processed_events"`
	AverageLatency   time.Duration `json:"average_latency"`
	LastUpdate       time.Time     `json:"last_update"`
}

type Workflow struct {
	ID          string             `json:"id"`
	Name        string             `json:"name"`
	Description string             `json:"description"`
	Steps       []*WorkflowStep    `json:"steps"`
	Triggers    []*WorkflowTrigger `json:"triggers"`
	Status      string             `json:"status"`
	Created     time.Time          `json:"created"`
	Updated     time.Time          `json:"updated"`
}

type WorkflowStep struct {
	ID         string                 `json:"id"`
	Name       string                 `json:"name"`
	Type       string                 `json:"type"`
	Action     string                 `json:"action"`
	Parameters map[string]interface{} `json:"parameters"`
	Condition  string                 `json:"condition"`
	NextStep   string                 `json:"next_step"`
}

type WorkflowTrigger struct {
	Type       string                 `json:"type"`
	Event      string                 `json:"event"`
	Condition  string                 `json:"condition"`
	Parameters map[string]interface{} `json:"parameters"`
	Enabled    bool                   `json:"enabled"`
}

type WorkflowScheduler struct {
	Enabled  bool                   `json:"enabled"`
	Queue    []string               `json:"queue"`
	Schedule string                 `json:"schedule"`
	Config   map[string]interface{} `json:"config"`
	LastRun  time.Time              `json:"last_run"`
}

type WorkflowExecutor struct {
	MaxConcurrent int                    `json:"max_concurrent"`
	Timeout       time.Duration          `json:"timeout"`
	RetryPolicy   *RetryPolicy           `json:"retry_policy"`
	Config        map[string]interface{} `json:"config"`
}

type WorkflowMonitor struct {
	Enabled   bool                   `json:"enabled"`
	Metrics   map[string]float64     `json:"metrics"`
	Alerts    []string               `json:"alerts"`
	LastCheck time.Time              `json:"last_check"`
	Config    map[string]interface{} `json:"config"`
}

type Playbook struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Version     string                 `json:"version"`
	Author      string                 `json:"author"`
	Steps       []*PlaybookStep        `json:"steps"`
	Variables   map[string]interface{} `json:"variables"`
	Created     time.Time              `json:"created"`
	Updated     time.Time              `json:"updated"`
}

type PlaybookExecutor struct {
	MaxConcurrent int                    `json:"max_concurrent"`
	Timeout       time.Duration          `json:"timeout"`
	RetryPolicy   *RetryPolicy           `json:"retry_policy"`
	Config        map[string]interface{} `json:"config"`
}

type PlaybookScheduler struct {
	Enabled  bool                   `json:"enabled"`
	Queue    []string               `json:"queue"`
	Schedule string                 `json:"schedule"`
	Config   map[string]interface{} `json:"config"`
	LastRun  time.Time              `json:"last_run"`
}

type PlaybookMonitor struct {
	Enabled   bool                   `json:"enabled"`
	Metrics   map[string]float64     `json:"metrics"`
	Alerts    []string               `json:"alerts"`
	LastCheck time.Time              `json:"last_check"`
	Config    map[string]interface{} `json:"config"`
}

type Action struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Type        string                 `json:"type"`
	Description string                 `json:"description"`
	Handler     string                 `json:"handler"`
	Parameters  map[string]interface{} `json:"parameters"`
	Timeout     time.Duration          `json:"timeout"`
	Enabled     bool                   `json:"enabled"`
}

type ResponseTrigger struct {
	Type       string                 `json:"type"`
	Event      string                 `json:"event"`
	Condition  string                 `json:"condition"`
	Parameters map[string]interface{} `json:"parameters"`
	Enabled    bool                   `json:"enabled"`
}

type ResponseCondition struct {
	Field     string      `json:"field"`
	Operator  string      `json:"operator"`
	Value     interface{} `json:"value"`
	LogicalOp string      `json:"logical_op"`
}

type ResponseExecutor struct {
	MaxConcurrent int                    `json:"max_concurrent"`
	Timeout       time.Duration          `json:"timeout"`
	RetryPolicy   *RetryPolicy           `json:"retry_policy"`
	Config        map[string]interface{} `json:"config"`
}

type Template struct {
	ID         string                 `json:"id"`
	Name       string                 `json:"name"`
	Type       string                 `json:"type"`
	Content    string                 `json:"content"`
	Variables  []string               `json:"variables"`
	Format     string                 `json:"format"`
	Parameters map[string]interface{} `json:"parameters"`
	Created    time.Time              `json:"created"`
	Updated    time.Time              `json:"updated"`
}

type ReportGenerator struct {
	Engines   map[string]interface{} `json:"engines"`
	Templates map[string]*Template   `json:"templates"`
	Config    map[string]interface{} `json:"config"`
}

type Job struct {
	ID         string                 `json:"id"`
	Name       string                 `json:"name"`
	Type       string                 `json:"type"`
	Handler    string                 `json:"handler"`
	Parameters map[string]interface{} `json:"parameters"`
	Priority   int                    `json:"priority"`
	Status     string                 `json:"status"`
	Created    time.Time              `json:"created"`
	Started    *time.Time             `json:"started"`
	Completed  *time.Time             `json:"completed"`
}

type JobQueue struct {
	Size     int                    `json:"size"`
	MaxSize  int                    `json:"max_size"`
	Jobs     []string               `json:"jobs"`
	Priority string                 `json:"priority"`
	Config   map[string]interface{} `json:"config"`
}

type JobExecutor struct {
	MaxConcurrent int                    `json:"max_concurrent"`
	Timeout       time.Duration          `json:"timeout"`
	RetryPolicy   *RetryPolicy           `json:"retry_policy"`
	Workers       int                    `json:"workers"`
	Config        map[string]interface{} `json:"config"`
}

type JobMonitor struct {
	Enabled   bool                   `json:"enabled"`
	Metrics   map[string]float64     `json:"metrics"`
	Alerts    []string               `json:"alerts"`
	LastCheck time.Time              `json:"last_check"`
	Config    map[string]interface{} `json:"config"`
}

type RetryPolicy struct {
	MaxRetries int           `json:"max_retries"`
	Backoff    time.Duration `json:"backoff"`
	Strategy   string        `json:"strategy"`
	Enabled    bool          `json:"enabled"`
}

// Additional missing hunting types
type ThreatIntelligenceEngine struct {
	ID          string                 `json:"id"`
	Sources     []*IOCSource           `json:"sources"`
	Feeds       map[string]interface{} `json:"feeds"`
	Enrichment  *IOCEnrichment         `json:"enrichment"`
	Analytics   *IOCAnalyzer           `json:"analytics"`
	Config      map[string]interface{} `json:"config"`
	Performance *EnginePerformance     `json:"performance"`
}

type HypothesisGenerator struct {
	ID         string                 `json:"id"`
	Templates  []string               `json:"templates"`
	Models     []*HuntingModel        `json:"models"`
	Strategies []*HuntStrategy        `json:"strategies"`
	Config     map[string]interface{} `json:"config"`
}

type InvestigationEngine struct {
	ID          string                 `json:"id"`
	Tools       []string               `json:"tools"`
	Procedures  []*InvestigationStep   `json:"procedures"`
	Evidence    *EvidenceCollector     `json:"evidence"`
	Analytics   *HuntingAnalytics      `json:"analytics"`
	Config      map[string]interface{} `json:"config"`
	Performance *EnginePerformance     `json:"performance"`
}

type HuntingWorkflow struct {
	ID      string                 `json:"id"`
	Name    string                 `json:"name"`
	Steps   []*WorkflowStep        `json:"steps"`
	Status  string                 `json:"status"`
	Context map[string]interface{} `json:"context"`
	Created time.Time              `json:"created"`
	Updated time.Time              `json:"updated"`
}

type ThreatKnowledgeBase struct {
	ID          string                        `json:"id"`
	TTPs        map[string]*TTPKnowledge      `json:"ttps"`
	IOCs        map[string]*IOCKnowledge      `json:"iocs"`
	Actors      map[string]*ActorKnowledge    `json:"actors"`
	Campaigns   map[string]*CampaignKnowledge `json:"campaigns"`
	Config      map[string]interface{}        `json:"config"`
	LastUpdated time.Time                     `json:"last_updated"`
}

type CollaborationEngine struct {
	ID          string                 `json:"id"`
	Teams       []*TeamMember          `json:"teams"`
	Channels    []string               `json:"channels"`
	Workflows   []*HuntingWorkflow     `json:"workflows"`
	Config      map[string]interface{} `json:"config"`
	Performance *EnginePerformance     `json:"performance"`
}

type AutomationEngine struct {
	ID          string                 `json:"id"`
	Rules       []*AutomationRule      `json:"rules"`
	Triggers    []*AutomationTrigger   `json:"triggers"`
	Actions     []*AutomationAction    `json:"actions"`
	Scheduler   *AutomationScheduler   `json:"scheduler"`
	Config      map[string]interface{} `json:"config"`
	Performance *EnginePerformance     `json:"performance"`
}

type VisualizationEngine struct {
	ID          string                 `json:"id"`
	Charts      map[string]*Chart      `json:"charts"`
	Dashboards  map[string]*Dashboard  `json:"dashboards"`
	Renderer    *ChartRenderer         `json:"renderer"`
	Config      map[string]interface{} `json:"config"`
	Performance *EnginePerformance     `json:"performance"`
}

type IndicatorFusion struct {
	ID       string                 `json:"id"`
	Sources  []*IOCSource           `json:"sources"`
	Fusers   []string               `json:"fusers"`
	Rules    []*FusionRule          `json:"rules"`
	Config   map[string]interface{} `json:"config"`
	LastSync time.Time              `json:"last_sync"`
}

type UserBehaviorAnalyzer struct {
	ID          string                      `json:"id"`
	Profiles    map[string]*BehaviorProfile `json:"profiles"`
	Models      []*BehaviorModel            `json:"models"`
	Anomalies   []*BehaviorAnomaly          `json:"anomalies"`
	Baselines   map[string]*Baseline        `json:"baselines"`
	Config      map[string]interface{}      `json:"config"`
	Performance *EnginePerformance          `json:"performance"`
}

// Support types for the above engines
type InvestigationStep struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Type        string                 `json:"type"`
	Description string                 `json:"description"`
	Tool        string                 `json:"tool"`
	Parameters  map[string]interface{} `json:"parameters"`
	NextStep    string                 `json:"next_step"`
}

type AutomationRule struct {
	ID        string                 `json:"id"`
	Name      string                 `json:"name"`
	Condition string                 `json:"condition"`
	Action    string                 `json:"action"`
	Priority  int                    `json:"priority"`
	Enabled   bool                   `json:"enabled"`
	Config    map[string]interface{} `json:"config"`
}

type AutomationScheduler struct {
	ID       string                 `json:"id"`
	Schedule string                 `json:"schedule"`
	Queue    []string               `json:"queue"`
	Active   bool                   `json:"active"`
	Config   map[string]interface{} `json:"config"`
}

type Dashboard struct {
	ID      string                 `json:"id"`
	Name    string                 `json:"name"`
	Type    string                 `json:"type"`
	Layout  string                 `json:"layout"`
	Widgets []string               `json:"widgets"`
	Config  map[string]interface{} `json:"config"`
	Created time.Time              `json:"created"`
	Updated time.Time              `json:"updated"`
}

type FusionRule struct {
	ID         string                 `json:"id"`
	Name       string                 `json:"name"`
	Sources    []string               `json:"sources"`
	Logic      string                 `json:"logic"`
	Priority   int                    `json:"priority"`
	Enabled    bool                   `json:"enabled"`
	Parameters map[string]interface{} `json:"parameters"`
}

// Additional behavior analyzers and anomaly detectors
type NetworkBehaviorAnalyzer struct {
	ID          string                 `json:"id"`
	Flows       []*NetworkFlow         `json:"flows"`
	Topology    *NetworkTopology       `json:"topology"`
	Patterns    map[string]*Pattern    `json:"patterns"`
	Anomalies   []*NetworkAnomaly      `json:"anomalies"`
	Config      map[string]interface{} `json:"config"`
	Performance *EnginePerformance     `json:"performance"`
}

type SystemBehaviorAnalyzer struct {
	ID          string                 `json:"id"`
	Processes   []*ProcessInfo         `json:"processes"`
	Resources   *ResourceUsage         `json:"resources"`
	Events      []*SystemEvent         `json:"events"`
	Baselines   map[string]*Baseline   `json:"baselines"`
	Config      map[string]interface{} `json:"config"`
	Performance *EnginePerformance     `json:"performance"`
}

type ApplicationBehaviorAnalyzer struct {
	ID           string                 `json:"id"`
	Applications map[string]*AppProfile `json:"applications"`
	Traces       []*ApplicationTrace    `json:"traces"`
	Metrics      map[string]float64     `json:"metrics"`
	Anomalies    []*AppAnomaly          `json:"anomalies"`
	Config       map[string]interface{} `json:"config"`
	Performance  *EnginePerformance     `json:"performance"`
}

type DataflowAnalyzer struct {
	ID          string                 `json:"id"`
	Flows       []*DataFlow            `json:"flows"`
	Pipelines   []*DataPipeline        `json:"pipelines"`
	Lineage     *DataLineage           `json:"lineage"`
	Quality     *DataQuality           `json:"quality"`
	Config      map[string]interface{} `json:"config"`
	Performance *EnginePerformance     `json:"performance"`
}

type AccessPatternAnalyzer struct {
	ID          string                  `json:"id"`
	Patterns    []*AccessPattern        `json:"patterns"`
	Users       map[string]*UserProfile `json:"users"`
	Resources   []*ResourceAccess       `json:"resources"`
	Anomalies   []*AccessAnomaly        `json:"anomalies"`
	Config      map[string]interface{}  `json:"config"`
	Performance *EnginePerformance      `json:"performance"`
}

type GeospatialAnalyzer struct {
	ID          string                 `json:"id"`
	Locations   []*Location            `json:"locations"`
	Patterns    []*GeoPattern          `json:"patterns"`
	Anomalies   []*GeoAnomaly          `json:"anomalies"`
	Maps        map[string]*GeoMap     `json:"maps"`
	Config      map[string]interface{} `json:"config"`
	Performance *EnginePerformance     `json:"performance"`
}

type StatisticalAnomalyDetector struct {
	ID          string                 `json:"id"`
	Statistics  []*StatisticDefinition `json:"statistics"`
	Tests       []*StatisticalTest     `json:"tests"`
	Thresholds  map[string]float64     `json:"thresholds"`
	Anomalies   []*StatisticalAnomaly  `json:"anomalies"`
	Config      map[string]interface{} `json:"config"`
	Performance *EnginePerformance     `json:"performance"`
}

type MLAnomalyDetector struct {
	ID          string                 `json:"id"`
	Models      []*HuntingModel        `json:"models"`
	Features    []string               `json:"features"`
	Predictions []*AnomalyPrediction   `json:"predictions"`
	Anomalies   []*MLAnomaly           `json:"anomalies"`
	Config      map[string]interface{} `json:"config"`
	Performance *EnginePerformance     `json:"performance"`
}

type TimeSeriesAnomalyDetector struct {
	ID          string                 `json:"id"`
	Series      []*TimeSeries          `json:"series"`
	Models      []*TimeSeriesModel     `json:"models"`
	Forecasts   []*Forecast            `json:"forecasts"`
	Anomalies   []*TimeSeriesAnomaly   `json:"anomalies"`
	Config      map[string]interface{} `json:"config"`
	Performance *EnginePerformance     `json:"performance"`
}

type ClusteringAnomalyDetector struct {
	ID          string                 `json:"id"`
	Clusters    []*Cluster             `json:"clusters"`
	Algorithm   string                 `json:"algorithm"`
	Distance    string                 `json:"distance"`
	Anomalies   []*ClusterAnomaly      `json:"anomalies"`
	Config      map[string]interface{} `json:"config"`
	Performance *EnginePerformance     `json:"performance"`
}

// Support types for the above analyzers
type ProcessInfo struct {
	PID       int       `json:"pid"`
	Name      string    `json:"name"`
	Command   string    `json:"command"`
	User      string    `json:"user"`
	CPU       float64   `json:"cpu"`
	Memory    float64   `json:"memory"`
	StartTime time.Time `json:"start_time"`
}

type ResourceUsage struct {
	CPU       float64   `json:"cpu"`
	Memory    float64   `json:"memory"`
	Disk      float64   `json:"disk"`
	Network   float64   `json:"network"`
	Timestamp time.Time `json:"timestamp"`
}

type SystemEvent struct {
	ID        string    `json:"id"`
	Type      string    `json:"type"`
	Source    string    `json:"source"`
	Message   string    `json:"message"`
	Severity  string    `json:"severity"`
	Timestamp time.Time `json:"timestamp"`
}

type AppProfile struct {
	Name       string             `json:"name"`
	Version    string             `json:"version"`
	Type       string             `json:"type"`
	Metrics    map[string]float64 `json:"metrics"`
	LastUpdate time.Time          `json:"last_update"`
}

type ApplicationTrace struct {
	ID        string    `json:"id"`
	App       string    `json:"app"`
	Operation string    `json:"operation"`
	Duration  float64   `json:"duration"`
	Status    string    `json:"status"`
	Timestamp time.Time `json:"timestamp"`
}

type AppAnomaly struct {
	App       string    `json:"app"`
	Type      string    `json:"type"`
	Severity  float64   `json:"severity"`
	Details   string    `json:"details"`
	Timestamp time.Time `json:"timestamp"`
}

type DataFlow struct {
	ID          string    `json:"id"`
	Source      string    `json:"source"`
	Destination string    `json:"destination"`
	Type        string    `json:"type"`
	Volume      int64     `json:"volume"`
	Timestamp   time.Time `json:"timestamp"`
}

type DataPipeline struct {
	ID      string             `json:"id"`
	Name    string             `json:"name"`
	Stages  []*DataStage       `json:"stages"`
	Status  string             `json:"status"`
	Metrics map[string]float64 `json:"metrics"`
}

type DataStage struct {
	ID     string                 `json:"id"`
	Name   string                 `json:"name"`
	Type   string                 `json:"type"`
	Config map[string]interface{} `json:"config"`
	Status string                 `json:"status"`
}

type DataLineage struct {
	Sources         []string  `json:"sources"`
	Destinations    []string  `json:"destinations"`
	Transformations []string  `json:"transformations"`
	Updated         time.Time `json:"updated"`
}

type DataQuality struct {
	Score     float64            `json:"score"`
	Issues    []string           `json:"issues"`
	Metrics   map[string]float64 `json:"metrics"`
	LastCheck time.Time          `json:"last_check"`
}

type AccessPattern struct {
	User       string    `json:"user"`
	Resource   string    `json:"resource"`
	Action     string    `json:"action"`
	Frequency  int       `json:"frequency"`
	LastAccess time.Time `json:"last_access"`
}

type ResourceAccess struct {
	Resource   string    `json:"resource"`
	Users      []string  `json:"users"`
	Actions    []string  `json:"actions"`
	LastAccess time.Time `json:"last_access"`
}

type AccessAnomaly struct {
	User      string    `json:"user"`
	Resource  string    `json:"resource"`
	Type      string    `json:"type"`
	Severity  float64   `json:"severity"`
	Timestamp time.Time `json:"timestamp"`
}

type Location struct {
	Latitude  float64   `json:"latitude"`
	Longitude float64   `json:"longitude"`
	Country   string    `json:"country"`
	City      string    `json:"city"`
	IP        string    `json:"ip"`
	Timestamp time.Time `json:"timestamp"`
}

type GeoPattern struct {
	Region    string    `json:"region"`
	Pattern   string    `json:"pattern"`
	Frequency int       `json:"frequency"`
	LastSeen  time.Time `json:"last_seen"`
}

type GeoAnomaly struct {
	Location  *Location `json:"location"`
	Type      string    `json:"type"`
	Severity  float64   `json:"severity"`
	Details   string    `json:"details"`
	Timestamp time.Time `json:"timestamp"`
}

type GeoMap struct {
	ID     string                 `json:"id"`
	Name   string                 `json:"name"`
	Layers []string               `json:"layers"`
	Bounds map[string]float64     `json:"bounds"`
	Config map[string]interface{} `json:"config"`
}

type StatisticalAnomaly struct {
	Metric    string    `json:"metric"`
	Value     float64   `json:"value"`
	Expected  float64   `json:"expected"`
	Deviation float64   `json:"deviation"`
	Timestamp time.Time `json:"timestamp"`
}

type AnomalyPrediction struct {
	Type        string    `json:"type"`
	Probability float64   `json:"probability"`
	Confidence  float64   `json:"confidence"`
	Timestamp   time.Time `json:"timestamp"`
}

type MLAnomaly struct {
	Features   map[string]float64 `json:"features"`
	Score      float64            `json:"score"`
	Type       string             `json:"type"`
	Prediction string             `json:"prediction"`
	Timestamp  time.Time          `json:"timestamp"`
}

type TimeSeries struct {
	ID         string      `json:"id"`
	Name       string      `json:"name"`
	Values     []float64   `json:"values"`
	Timestamps []time.Time `json:"timestamps"`
	Frequency  string      `json:"frequency"`
}

type TimeSeriesAnomaly struct {
	Series    string    `json:"series"`
	Index     int       `json:"index"`
	Value     float64   `json:"value"`
	Expected  float64   `json:"expected"`
	Score     float64   `json:"score"`
	Timestamp time.Time `json:"timestamp"`
}

type Cluster struct {
	ID       string    `json:"id"`
	Centroid []float64 `json:"centroid"`
	Members  []string  `json:"members"`
	Size     int       `json:"size"`
	Variance float64   `json:"variance"`
}

type ClusterAnomaly struct {
	Point     []float64 `json:"point"`
	Cluster   string    `json:"cluster"`
	Distance  float64   `json:"distance"`
	Score     float64   `json:"score"`
	Timestamp time.Time `json:"timestamp"`
}

// Additional anomaly detectors and correlators
type OutlierDetector struct {
	ID          string                 `json:"id"`
	Algorithm   string                 `json:"algorithm"`
	Threshold   float64                `json:"threshold"`
	Features    []string               `json:"features"`
	Outliers    []*Outlier             `json:"outliers"`
	Config      map[string]interface{} `json:"config"`
	Performance *EnginePerformance     `json:"performance"`
}

type ChangePointDetector struct {
	ID           string                 `json:"id"`
	Algorithm    string                 `json:"algorithm"`
	Window       int                    `json:"window"`
	Sensitivity  float64                `json:"sensitivity"`
	ChangePoints []*ChangePoint         `json:"change_points"`
	Config       map[string]interface{} `json:"config"`
	Performance  *EnginePerformance     `json:"performance"`
}

type SeasonalityDetector struct {
	ID          string                 `json:"id"`
	Periods     []int                  `json:"periods"`
	Method      string                 `json:"method"`
	Patterns    []*SeasonalPattern     `json:"patterns"`
	Anomalies   []*SeasonalAnomaly     `json:"anomalies"`
	Config      map[string]interface{} `json:"config"`
	Performance *EnginePerformance     `json:"performance"`
}

type MultivariateAnomalyDetector struct {
	ID           string                 `json:"id"`
	Variables    []string               `json:"variables"`
	Model        *HuntingModel          `json:"model"`
	Correlations map[string]float64     `json:"correlations"`
	Anomalies    []*MultivariateAnomaly `json:"anomalies"`
	Config       map[string]interface{} `json:"config"`
	Performance  *EnginePerformance     `json:"performance"`
}

type TemporalCorrelator struct {
	ID           string                 `json:"id"`
	TimeWindow   time.Duration          `json:"time_window"`
	Rules        []*TemporalRule        `json:"rules"`
	Events       []*TemporalEvent       `json:"events"`
	Correlations []*TemporalCorrelation `json:"correlations"`
	Config       map[string]interface{} `json:"config"`
	Performance  *EnginePerformance     `json:"performance"`
}

type SpatialCorrelator struct {
	ID           string                 `json:"id"`
	Radius       float64                `json:"radius"`
	Rules        []*SpatialRule         `json:"rules"`
	Locations    []*Location            `json:"locations"`
	Correlations []*SpatialCorrelation  `json:"correlations"`
	Config       map[string]interface{} `json:"config"`
	Performance  *EnginePerformance     `json:"performance"`
}

type EntityCorrelator struct {
	ID           string                 `json:"id"`
	Entities     map[string]*Entity     `json:"entities"`
	Rules        []*EntityRule          `json:"rules"`
	Relations    []*EntityRelation      `json:"relations"`
	Correlations []*EntityCorrelation   `json:"correlations"`
	Config       map[string]interface{} `json:"config"`
	Performance  *EnginePerformance     `json:"performance"`
}

type PatternCorrelator struct {
	ID           string                 `json:"id"`
	Patterns     []*Pattern             `json:"patterns"`
	Rules        []*PatternRule         `json:"rules"`
	Matches      []*PatternMatch        `json:"matches"`
	Correlations []*PatternCorrelation  `json:"correlations"`
	Config       map[string]interface{} `json:"config"`
	Performance  *EnginePerformance     `json:"performance"`
}

type CorrelationRuleEngine struct {
	ID          string                 `json:"id"`
	Rules       []*CorrelationRule     `json:"rules"`
	Engine      string                 `json:"engine"`
	Evaluator   *RuleEvaluator         `json:"evaluator"`
	Results     []*CorrelationResult   `json:"results"`
	Config      map[string]interface{} `json:"config"`
	Performance *EnginePerformance     `json:"performance"`
}

type GraphCorrelationAnalyzer struct {
	ID          string                 `json:"id"`
	Graph       *CorrelationGraph      `json:"graph"`
	Algorithms  []string               `json:"algorithms"`
	Communities []*GraphCommunity      `json:"communities"`
	Paths       []*GraphPath           `json:"paths"`
	Config      map[string]interface{} `json:"config"`
	Performance *EnginePerformance     `json:"performance"`
}

// Support types for the above detectors and correlators
type Outlier struct {
	ID        string                 `json:"id"`
	Value     interface{}            `json:"value"`
	Score     float64                `json:"score"`
	Type      string                 `json:"type"`
	Context   map[string]interface{} `json:"context"`
	Timestamp time.Time              `json:"timestamp"`
}

type ChangePoint struct {
	Index      int       `json:"index"`
	Timestamp  time.Time `json:"timestamp"`
	Confidence float64   `json:"confidence"`
	Type       string    `json:"type"`
	Magnitude  float64   `json:"magnitude"`
}

type SeasonalPattern struct {
	Period     int       `json:"period"`
	Amplitude  float64   `json:"amplitude"`
	Phase      float64   `json:"phase"`
	Confidence float64   `json:"confidence"`
	LastSeen   time.Time `json:"last_seen"`
}

type SeasonalAnomaly struct {
	Pattern   string    `json:"pattern"`
	Expected  float64   `json:"expected"`
	Actual    float64   `json:"actual"`
	Deviation float64   `json:"deviation"`
	Timestamp time.Time `json:"timestamp"`
}

type MultivariateAnomaly struct {
	Variables map[string]float64 `json:"variables"`
	Score     float64            `json:"score"`
	Type      string             `json:"type"`
	Rank      int                `json:"rank"`
	Timestamp time.Time          `json:"timestamp"`
}

type TemporalRule struct {
	ID        string        `json:"id"`
	Condition string        `json:"condition"`
	Window    time.Duration `json:"window"`
	Threshold int           `json:"threshold"`
	Enabled   bool          `json:"enabled"`
}

type TemporalEvent struct {
	ID        string                 `json:"id"`
	Type      string                 `json:"type"`
	Source    string                 `json:"source"`
	Data      map[string]interface{} `json:"data"`
	Timestamp time.Time              `json:"timestamp"`
}

type TemporalCorrelation struct {
	Events    []string      `json:"events"`
	TimeSpan  time.Duration `json:"time_span"`
	Score     float64       `json:"score"`
	Type      string        `json:"type"`
	Timestamp time.Time     `json:"timestamp"`
}

type SpatialRule struct {
	ID        string  `json:"id"`
	Condition string  `json:"condition"`
	Radius    float64 `json:"radius"`
	Threshold int     `json:"threshold"`
	Enabled   bool    `json:"enabled"`
}

type SpatialCorrelation struct {
	Locations []string  `json:"locations"`
	Distance  float64   `json:"distance"`
	Score     float64   `json:"score"`
	Type      string    `json:"type"`
	Timestamp time.Time `json:"timestamp"`
}

type Entity struct {
	ID         string                 `json:"id"`
	Type       string                 `json:"type"`
	Properties map[string]interface{} `json:"properties"`
	Relations  []string               `json:"relations"`
	LastUpdate time.Time              `json:"last_update"`
}

type EntityRule struct {
	ID        string   `json:"id"`
	Condition string   `json:"condition"`
	Entities  []string `json:"entities"`
	Threshold int      `json:"threshold"`
	Enabled   bool     `json:"enabled"`
}

type EntityRelation struct {
	Source     string                 `json:"source"`
	Target     string                 `json:"target"`
	Type       string                 `json:"type"`
	Weight     float64                `json:"weight"`
	Properties map[string]interface{} `json:"properties"`
}

type EntityCorrelation struct {
	Entities  []string  `json:"entities"`
	Relations []string  `json:"relations"`
	Score     float64   `json:"score"`
	Type      string    `json:"type"`
	Timestamp time.Time `json:"timestamp"`
}

type PatternRule struct {
	ID        string  `json:"id"`
	Pattern   string  `json:"pattern"`
	Condition string  `json:"condition"`
	Threshold float64 `json:"threshold"`
	Enabled   bool    `json:"enabled"`
}

type PatternMatch struct {
	Pattern   string    `json:"pattern"`
	Data      string    `json:"data"`
	Score     float64   `json:"score"`
	Position  int       `json:"position"`
	Timestamp time.Time `json:"timestamp"`
}

type PatternCorrelation struct {
	Patterns  []string  `json:"patterns"`
	Matches   []string  `json:"matches"`
	Score     float64   `json:"score"`
	Type      string    `json:"type"`
	Timestamp time.Time `json:"timestamp"`
}

type RuleEvaluator struct {
	Engine    string                 `json:"engine"`
	Context   map[string]interface{} `json:"context"`
	Functions map[string]interface{} `json:"functions"`
	Variables map[string]interface{} `json:"variables"`
}

type CorrelationResult struct {
	RuleID    string                 `json:"rule_id"`
	Score     float64                `json:"score"`
	Evidence  []string               `json:"evidence"`
	Context   map[string]interface{} `json:"context"`
	Timestamp time.Time              `json:"timestamp"`
}

type CorrelationGraph struct {
	Nodes      []*GraphNode           `json:"nodes"`
	Edges      []*GraphEdge           `json:"edges"`
	Properties map[string]interface{} `json:"properties"`
	Updated    time.Time              `json:"updated"`
}

type GraphNode struct {
	ID         string                 `json:"id"`
	Type       string                 `json:"type"`
	Label      string                 `json:"label"`
	Properties map[string]interface{} `json:"properties"`
}

type GraphEdge struct {
	Source     string                 `json:"source"`
	Target     string                 `json:"target"`
	Type       string                 `json:"type"`
	Weight     float64                `json:"weight"`
	Properties map[string]interface{} `json:"properties"`
}

type GraphCommunity struct {
	ID       string    `json:"id"`
	Nodes    []string  `json:"nodes"`
	Score    float64   `json:"score"`
	Type     string    `json:"type"`
	Detected time.Time `json:"detected"`
}

type GraphPath struct {
	Source string   `json:"source"`
	Target string   `json:"target"`
	Nodes  []string `json:"nodes"`
	Length int      `json:"length"`
	Weight float64  `json:"weight"`
}

// Additional threat analysis and AI hunting types
type AttackChainReconstructor struct {
	ID            string                    `json:"id"`
	Chains        []*AttackChain            `json:"chains"`
	Techniques    map[string]*TechniqueInfo `json:"techniques"`
	Patterns      []*ChainPattern           `json:"patterns"`
	Reconstructed []*ReconstructedChain     `json:"reconstructed"`
	Config        map[string]interface{}    `json:"config"`
	Performance   *EnginePerformance        `json:"performance"`
}

type ThreatFeedManager struct {
	ID          string                 `json:"id"`
	Feeds       []*ThreatFeed          `json:"feeds"`
	Sources     []*IOCSource           `json:"sources"`
	Parser      *FeedParser            `json:"parser"`
	Enricher    *FeedEnricher          `json:"enricher"`
	Config      map[string]interface{} `json:"config"`
	Performance *EnginePerformance     `json:"performance"`
}

type ThreatEnrichmentEngine struct {
	ID          string                 `json:"id"`
	Enrichers   []*ThreatEnricher      `json:"enrichers"`
	Sources     []*EnrichmentSource    `json:"sources"`
	Cache       *EnrichmentCache       `json:"cache"`
	Results     []*EnrichmentResult    `json:"results"`
	Config      map[string]interface{} `json:"config"`
	Performance *EnginePerformance     `json:"performance"`
}

type ThreatContextualizer struct {
	ID          string                  `json:"id"`
	Contexts    []*ThreatContext        `json:"contexts"`
	Rules       []*ContextRule          `json:"rules"`
	Enrichment  *ThreatEnrichmentEngine `json:"enrichment"`
	Knowledge   *ThreatKnowledgeBase    `json:"knowledge"`
	Config      map[string]interface{}  `json:"config"`
	Performance *EnginePerformance      `json:"performance"`
}

type AttributionEngine struct {
	ID           string                         `json:"id"`
	Actors       map[string]*ThreatActorProfile `json:"actors"`
	Campaigns    map[string]*Campaign           `json:"campaigns"`
	Techniques   map[string]*MITRETechnique     `json:"techniques"`
	Attributions []*Attribution                 `json:"attributions"`
	Config       map[string]interface{}         `json:"config"`
	Performance  *EnginePerformance             `json:"performance"`
}

type CampaignAnalyzer struct {
	ID          string                 `json:"id"`
	Campaigns   map[string]*Campaign   `json:"campaigns"`
	Tracker     *CampaignTracker       `json:"tracker"`
	Timeline    *CampaignTimeline      `json:"timeline"`
	Patterns    []*CampaignPattern     `json:"patterns"`
	Config      map[string]interface{} `json:"config"`
	Performance *EnginePerformance     `json:"performance"`
}

type TacticsAnalyzer struct {
	ID          string                  `json:"id"`
	Tactics     map[string]*MITRETactic `json:"tactics"`
	Mapper      *MITRETacticsMapper     `json:"mapper"`
	Sequences   []*TacticSequence       `json:"sequences"`
	Patterns    []*TacticPattern        `json:"patterns"`
	Config      map[string]interface{}  `json:"config"`
	Performance *EnginePerformance      `json:"performance"`
}

type TTpsMapper struct {
	ID          string                     `json:"id"`
	Tactics     map[string]*MITRETactic    `json:"tactics"`
	Techniques  map[string]*MITRETechnique `json:"techniques"`
	Procedures  map[string]*MITREProcedure `json:"procedures"`
	Mappings    []*TTPMapping              `json:"mappings"`
	Config      map[string]interface{}     `json:"config"`
	Performance *EnginePerformance         `json:"performance"`
}

type IntelligenceFusion struct {
	ID          string                 `json:"id"`
	Sources     []*IntelligenceSource  `json:"sources"`
	Fuser       *IntelligenceFuser     `json:"fuser"`
	Rules       []*FusionRule          `json:"rules"`
	Results     []*FusionResult        `json:"results"`
	Config      map[string]interface{} `json:"config"`
	Performance *EnginePerformance     `json:"performance"`
}

type AIHypothesisGenerator struct {
	ID          string                 `json:"id"`
	Models      []*HuntingModel        `json:"models"`
	Templates   []*HypothesisTemplate  `json:"templates"`
	Generator   *HypothesisAI          `json:"generator"`
	Hypotheses  []*AIHypothesis        `json:"hypotheses"`
	Config      map[string]interface{} `json:"config"`
	Performance *EnginePerformance     `json:"performance"`
}

// Support types for the above engines
type TechniqueInfo struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	MITRE       string   `json:"mitre"`
	Tactic      string   `json:"tactic"`
	Description string   `json:"description"`
	Indicators  []string `json:"indicators"`
}

type ReconstructedChain struct {
	ID         string        `json:"id"`
	Original   string        `json:"original"`
	Steps      []*AttackStep `json:"steps"`
	Confidence float64       `json:"confidence"`
	Timeline   []time.Time   `json:"timeline"`
	Complete   bool          `json:"complete"`
}

type ThreatFeed struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	URL         string                 `json:"url"`
	Type        string                 `json:"type"`
	Format      string                 `json:"format"`
	Frequency   time.Duration          `json:"frequency"`
	Reliability float64                `json:"reliability"`
	LastUpdate  time.Time              `json:"last_update"`
	Config      map[string]interface{} `json:"config"`
}

type FeedParser struct {
	Parsers map[string]*Parser     `json:"parsers"`
	Rules   []*ParsingRule         `json:"rules"`
	Config  map[string]interface{} `json:"config"`
}

type FeedEnricher struct {
	Enrichers map[string]*Enricher   `json:"enrichers"`
	Rules     []*EnrichmentRule      `json:"rules"`
	Config    map[string]interface{} `json:"config"`
}

type Enricher struct {
	Type    string                 `json:"type"`
	Source  string                 `json:"source"`
	Fields  []string               `json:"fields"`
	Handler string                 `json:"handler"`
	Config  map[string]interface{} `json:"config"`
}

type EnrichmentRule struct {
	Condition string                 `json:"condition"`
	Enricher  string                 `json:"enricher"`
	Priority  int                    `json:"priority"`
	Enabled   bool                   `json:"enabled"`
	Config    map[string]interface{} `json:"config"`
}

type ThreatEnricher struct {
	ID      string                 `json:"id"`
	Type    string                 `json:"type"`
	Sources []string               `json:"sources"`
	Handler string                 `json:"handler"`
	Cache   bool                   `json:"cache"`
	Config  map[string]interface{} `json:"config"`
}

type EnrichmentSource struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Type        string                 `json:"type"`
	URL         string                 `json:"url"`
	Reliability float64                `json:"reliability"`
	Cost        float64                `json:"cost"`
	Config      map[string]interface{} `json:"config"`
}

type EnrichmentCache struct {
	Size    int                    `json:"size"`
	TTL     time.Duration          `json:"ttl"`
	Entries map[string]*CacheEntry `json:"entries"`
	HitRate float64                `json:"hit_rate"`
	Config  map[string]interface{} `json:"config"`
}

type CacheEntry struct {
	Value     interface{}   `json:"value"`
	Timestamp time.Time     `json:"timestamp"`
	Hits      int           `json:"hits"`
	TTL       time.Duration `json:"ttl"`
}

type EnrichmentResult struct {
	IOC        string                 `json:"ioc"`
	Source     string                 `json:"source"`
	Data       map[string]interface{} `json:"data"`
	Confidence float64                `json:"confidence"`
	Timestamp  time.Time              `json:"timestamp"`
}

type CampaignPattern struct {
	Type       string    `json:"type"`
	Pattern    string    `json:"pattern"`
	Indicators []string  `json:"indicators"`
	Frequency  int       `json:"frequency"`
	LastSeen   time.Time `json:"last_seen"`
}

type TacticSequence struct {
	ID        string   `json:"id"`
	Tactics   []string `json:"tactics"`
	Order     []int    `json:"order"`
	Frequency int      `json:"frequency"`
	Campaigns []string `json:"campaigns"`
}

type TacticPattern struct {
	Pattern   string    `json:"pattern"`
	Tactics   []string  `json:"tactics"`
	Frequency int       `json:"frequency"`
	LastSeen  time.Time `json:"last_seen"`
}

type TTPMapping struct {
	Tactic     string   `json:"tactic"`
	Technique  string   `json:"technique"`
	Procedure  string   `json:"procedure"`
	IOCs       []string `json:"iocs"`
	Confidence float64  `json:"confidence"`
}

type IntelligenceSource struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Type        string                 `json:"type"`
	Reliability float64                `json:"reliability"`
	Timeliness  float64                `json:"timeliness"`
	Relevance   float64                `json:"relevance"`
	Config      map[string]interface{} `json:"config"`
}

type IntelligenceFuser struct {
	Algorithm string                 `json:"algorithm"`
	Weights   map[string]float64     `json:"weights"`
	Rules     []*FusionRule          `json:"rules"`
	Config    map[string]interface{} `json:"config"`
}

type FusionResult struct {
	IOC        string                 `json:"ioc"`
	Sources    []string               `json:"sources"`
	Score      float64                `json:"score"`
	Confidence float64                `json:"confidence"`
	Data       map[string]interface{} `json:"data"`
	Timestamp  time.Time              `json:"timestamp"`
}

type HypothesisTemplate struct {
	ID         string                 `json:"id"`
	Name       string                 `json:"name"`
	Template   string                 `json:"template"`
	Variables  []string               `json:"variables"`
	Category   string                 `json:"category"`
	Complexity string                 `json:"complexity"`
	Config     map[string]interface{} `json:"config"`
}

type HypothesisAI struct {
	Model     *HuntingModel          `json:"model"`
	NLP       *NLPProcessor          `json:"nlp"`
	Generator string                 `json:"generator"`
	Templates []*HypothesisTemplate  `json:"templates"`
	Config    map[string]interface{} `json:"config"`
}

type AIHypothesis struct {
	ID         string                 `json:"id"`
	Text       string                 `json:"text"`
	Category   string                 `json:"category"`
	Confidence float64                `json:"confidence"`
	Evidence   []string               `json:"evidence"`
	Template   string                 `json:"template"`
	Variables  map[string]interface{} `json:"variables"`
	Generated  time.Time              `json:"generated"`
}

// Final set of missing hunting engine types
type HypothesisTemplateEngine struct {
	ID          string                 `json:"id"`
	Templates   []*HypothesisTemplate  `json:"templates"`
	Engine      string                 `json:"engine"`
	Variables   map[string]interface{} `json:"variables"`
	Generated   []*AIHypothesis        `json:"generated"`
	Config      map[string]interface{} `json:"config"`
	Performance *EnginePerformance     `json:"performance"`
}

type ScenarioGenerator struct {
	ID          string                 `json:"id"`
	Templates   []*ScenarioTemplate    `json:"templates"`
	Generator   string                 `json:"generator"`
	Scenarios   []*HuntScenario        `json:"scenarios"`
	Context     map[string]interface{} `json:"context"`
	Config      map[string]interface{} `json:"config"`
	Performance *EnginePerformance     `json:"performance"`
}

type HypothesisRiskAssessment struct {
	ID          string                 `json:"id"`
	Assessor    string                 `json:"assessor"`
	Criteria    []*RiskCriteria        `json:"criteria"`
	Assessments []*RiskAssessment      `json:"assessments"`
	Matrix      *RiskMatrix            `json:"matrix"`
	Config      map[string]interface{} `json:"config"`
	Performance *EnginePerformance     `json:"performance"`
}

type HypothesisPrioritizer struct {
	ID          string                   `json:"id"`
	Algorithm   string                   `json:"algorithm"`
	Weights     map[string]float64       `json:"weights"`
	Priorities  []*HypothesisPriority    `json:"priorities"`
	Queue       []*PrioritizedHypothesis `json:"queue"`
	Config      map[string]interface{}   `json:"config"`
	Performance *EnginePerformance       `json:"performance"`
}

type HypothesisValidator struct {
	ID          string                 `json:"id"`
	Validators  []*Validator           `json:"validators"`
	Rules       []*ValidationRule      `json:"rules"`
	Results     []*ValidationResult    `json:"results"`
	Statistics  *ValidationStats       `json:"statistics"`
	Config      map[string]interface{} `json:"config"`
	Performance *EnginePerformance     `json:"performance"`
}

type HypothesisRefinementEngine struct {
	ID          string                 `json:"id"`
	Refiners    []*HypothesisRefiner   `json:"refiners"`
	Feedback    []*RefinementFeedback  `json:"feedback"`
	Refined     []*RefinedHypothesis   `json:"refined"`
	Learning    *RefinementLearning    `json:"learning"`
	Config      map[string]interface{} `json:"config"`
	Performance *EnginePerformance     `json:"performance"`
}

type CreativityEngine struct {
	ID          string                 `json:"id"`
	Algorithms  []string               `json:"algorithms"`
	Inspiration []*CreativeSource      `json:"inspiration"`
	Ideas       []*CreativeIdea        `json:"ideas"`
	Evaluation  *CreativityEvaluation  `json:"evaluation"`
	Config      map[string]interface{} `json:"config"`
	Performance *EnginePerformance     `json:"performance"`
}

type InvestigationManager struct {
	ID             string                   `json:"id"`
	Investigations []*ThreatInvestigation   `json:"investigations"`
	Workflows      []*InvestigationWorkflow `json:"workflows"`
	Resources      []*InvestigationResource `json:"resources"`
	Status         *InvestigationStatus     `json:"status"`
	Config         map[string]interface{}   `json:"config"`
	Performance    *EnginePerformance       `json:"performance"`
}

type EvidenceAnalyzer struct {
	ID          string                 `json:"id"`
	Analyzer    string                 `json:"analyzer"`
	Evidence    []*Evidence            `json:"evidence"`
	Analysis    []*EvidenceAnalysis    `json:"analysis"`
	Chain       *EvidenceChain         `json:"chain"`
	Config      map[string]interface{} `json:"config"`
	Performance *EnginePerformance     `json:"performance"`
}

type TimelineBuilder struct {
	ID          string                 `json:"id"`
	Builder     string                 `json:"builder"`
	Events      []*TimelineEvent       `json:"events"`
	Timeline    *InvestigationTimeline `json:"timeline"`
	Analysis    *TimelineAnalysis      `json:"analysis"`
	Config      map[string]interface{} `json:"config"`
	Performance *EnginePerformance     `json:"performance"`
}

// Support types for the above engines
type ScenarioTemplate struct {
	ID         string                 `json:"id"`
	Name       string                 `json:"name"`
	Category   string                 `json:"category"`
	Template   string                 `json:"template"`
	Variables  []string               `json:"variables"`
	Complexity string                 `json:"complexity"`
	Config     map[string]interface{} `json:"config"`
}

type HuntScenario struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Steps       []*ScenarioStep        `json:"steps"`
	Context     map[string]interface{} `json:"context"`
	Status      string                 `json:"status"`
	Created     time.Time              `json:"created"`
}

type ScenarioStep struct {
	ID         string                 `json:"id"`
	Name       string                 `json:"name"`
	Action     string                 `json:"action"`
	Parameters map[string]interface{} `json:"parameters"`
	Expected   string                 `json:"expected"`
	NextStep   string                 `json:"next_step"`
}

type RiskCriteria struct {
	ID          string  `json:"id"`
	Name        string  `json:"name"`
	Category    string  `json:"category"`
	Weight      float64 `json:"weight"`
	Threshold   float64 `json:"threshold"`
	Description string  `json:"description"`
}

type RiskAssessment struct {
	HypothesisID string             `json:"hypothesis_id"`
	Score        float64            `json:"score"`
	Level        string             `json:"level"`
	Factors      map[string]float64 `json:"factors"`
	Timestamp    time.Time          `json:"timestamp"`
}

type RiskMatrix struct {
	Levels     []string               `json:"levels"`
	Thresholds []float64              `json:"thresholds"`
	Colors     map[string]string      `json:"colors"`
	Actions    map[string][]string    `json:"actions"`
	Config     map[string]interface{} `json:"config"`
}

type HypothesisPriority struct {
	HypothesisID string    `json:"hypothesis_id"`
	Priority     string    `json:"priority"`
	Score        float64   `json:"score"`
	Rank         int       `json:"rank"`
	Assigned     time.Time `json:"assigned"`
}

type PrioritizedHypothesis struct {
	Hypothesis *AIHypothesis       `json:"hypothesis"`
	Priority   *HypothesisPriority `json:"priority"`
	Status     string              `json:"status"`
	Assigned   *time.Time          `json:"assigned"`
}

type ValidationResult struct {
	HypothesisID string    `json:"hypothesis_id"`
	ValidatorID  string    `json:"validator_id"`
	Valid        bool      `json:"valid"`
	Score        float64   `json:"score"`
	Issues       []string  `json:"issues"`
	Timestamp    time.Time `json:"timestamp"`
}

type ValidationStats struct {
	TotalValidated int       `json:"total_validated"`
	ValidCount     int       `json:"valid_count"`
	InvalidCount   int       `json:"invalid_count"`
	SuccessRate    float64   `json:"success_rate"`
	Updated        time.Time `json:"updated"`
}

type HypothesisRefiner struct {
	ID     string                 `json:"id"`
	Type   string                 `json:"type"`
	Model  *HuntingModel          `json:"model"`
	Rules  []*RefinementRule      `json:"rules"`
	Config map[string]interface{} `json:"config"`
}

type RefinementFeedback struct {
	HypothesisID string                 `json:"hypothesis_id"`
	Source       string                 `json:"source"`
	Type         string                 `json:"type"`
	Feedback     map[string]interface{} `json:"feedback"`
	Score        float64                `json:"score"`
	Timestamp    time.Time              `json:"timestamp"`
}

type RefinedHypothesis struct {
	Original  *AIHypothesis `json:"original"`
	Refined   *AIHypothesis `json:"refined"`
	Changes   []string      `json:"changes"`
	Score     float64       `json:"score"`
	Timestamp time.Time     `json:"timestamp"`
}

type RefinementLearning struct {
	Model       *HuntingModel     `json:"model"`
	Dataset     []*RefinementData `json:"dataset"`
	Accuracy    float64           `json:"accuracy"`
	LastTrained time.Time         `json:"last_trained"`
}

type RefinementRule struct {
	ID        string                 `json:"id"`
	Condition string                 `json:"condition"`
	Action    string                 `json:"action"`
	Priority  int                    `json:"priority"`
	Config    map[string]interface{} `json:"config"`
}

type RefinementData struct {
	Input     *AIHypothesis `json:"input"`
	Output    *AIHypothesis `json:"output"`
	Feedback  string        `json:"feedback"`
	Quality   float64       `json:"quality"`
	Timestamp time.Time     `json:"timestamp"`
}

type CreativeSource struct {
	ID      string                 `json:"id"`
	Type    string                 `json:"type"`
	Source  string                 `json:"source"`
	Content map[string]interface{} `json:"content"`
	Quality float64                `json:"quality"`
	Updated time.Time              `json:"updated"`
}

type CreativeIdea struct {
	ID          string    `json:"id"`
	Text        string    `json:"text"`
	Category    string    `json:"category"`
	Novelty     float64   `json:"novelty"`
	Feasibility float64   `json:"feasibility"`
	Sources     []string  `json:"sources"`
	Generated   time.Time `json:"generated"`
}

type CreativityEvaluation struct {
	Criteria []string               `json:"criteria"`
	Metrics  map[string]float64     `json:"metrics"`
	Scores   map[string]float64     `json:"scores"`
	Config   map[string]interface{} `json:"config"`
}

type InvestigationWorkflow struct {
	ID       string          `json:"id"`
	Name     string          `json:"name"`
	Steps    []*WorkflowStep `json:"steps"`
	Status   string          `json:"status"`
	Progress float64         `json:"progress"`
	Created  time.Time       `json:"created"`
}

type InvestigationResource struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"`
	Name        string                 `json:"name"`
	Location    string                 `json:"location"`
	Available   bool                   `json:"available"`
	Capacity    int                    `json:"capacity"`
	Utilization float64                `json:"utilization"`
	Config      map[string]interface{} `json:"config"`
}

type InvestigationStatus struct {
	Total      int            `json:"total"`
	Active     int            `json:"active"`
	Completed  int            `json:"completed"`
	Pending    int            `json:"pending"`
	ByPriority map[string]int `json:"by_priority"`
	ByStatus   map[string]int `json:"by_status"`
	Updated    time.Time      `json:"updated"`
}

type Evidence struct {
	ID        string                 `json:"id"`
	Type      string                 `json:"type"`
	Source    string                 `json:"source"`
	Data      map[string]interface{} `json:"data"`
	Hash      string                 `json:"hash"`
	Integrity bool                   `json:"integrity"`
	Relevance float64                `json:"relevance"`
	Collected time.Time              `json:"collected"`
}

type EvidenceAnalysis struct {
	EvidenceID string                 `json:"evidence_id"`
	AnalysisID string                 `json:"analysis_id"`
	Type       string                 `json:"type"`
	Results    map[string]interface{} `json:"results"`
	Confidence float64                `json:"confidence"`
	Anomalies  []string               `json:"anomalies"`
	Timestamp  time.Time              `json:"timestamp"`
}

type InvestigationTimeline struct {
	ID       string           `json:"id"`
	Name     string           `json:"name"`
	Events   []*TimelineEvent `json:"events"`
	Start    time.Time        `json:"start"`
	End      *time.Time       `json:"end"`
	Duration *time.Duration   `json:"duration"`
	Updated  time.Time        `json:"updated"`
}

type TimelineAnalysis struct {
	Patterns     []*TimelinePattern     `json:"patterns"`
	Gaps         []*TimelineGap         `json:"gaps"`
	Correlations []*TimelineCorrelation `json:"correlations"`
	Anomalies    []*TimelineAnomaly     `json:"anomalies"`
	Summary      string                 `json:"summary"`
	Updated      time.Time              `json:"updated"`
}

type TimelineGap struct {
	Start     time.Time     `json:"start"`
	End       time.Time     `json:"end"`
	Duration  time.Duration `json:"duration"`
	Potential []string      `json:"potential"`
	Impact    string        `json:"impact"`
}

type TimelineCorrelation struct {
	Events   []string      `json:"events"`
	Type     string        `json:"type"`
	Strength float64       `json:"strength"`
	TimeSpan time.Duration `json:"time_span"`
	Detected time.Time     `json:"detected"`
}

// Final remaining missing hunting types
type ForensicsEngine struct {
	ID          string                 `json:"id"`
	Tools       []*ForensicTool        `json:"tools"`
	Evidence    []*Evidence            `json:"evidence"`
	Analysis    []*ForensicAnalysis    `json:"analysis"`
	Chain       *EvidenceChain         `json:"chain"`
	Config      map[string]interface{} `json:"config"`
	Performance *EnginePerformance     `json:"performance"`
}

type RootCauseAnalyzer struct {
	ID          string                 `json:"id"`
	Analyzer    string                 `json:"analyzer"`
	Causes      []*RootCause           `json:"causes"`
	Analysis    []*CauseAnalysis       `json:"analysis"`
	Tree        *CauseTree             `json:"tree"`
	Config      map[string]interface{} `json:"config"`
	Performance *EnginePerformance     `json:"performance"`
}

type ImpactAssessment struct {
	ID          string                 `json:"id"`
	Assessor    string                 `json:"assessor"`
	Impacts     []*Impact              `json:"impacts"`
	Assessment  []*ImpactResult        `json:"assessment"`
	Matrix      *ImpactMatrix          `json:"matrix"`
	Config      map[string]interface{} `json:"config"`
	Performance *EnginePerformance     `json:"performance"`
}

type RemediationPlanner struct {
	ID          string                 `json:"id"`
	Planner     string                 `json:"planner"`
	Plans       []*RemediationPlan     `json:"plans"`
	Actions     []*RemediationAction   `json:"actions"`
	Scheduler   *RemediationScheduler  `json:"scheduler"`
	Config      map[string]interface{} `json:"config"`
	Performance *EnginePerformance     `json:"performance"`
}

type CaseworkEngine struct {
	ID          string                 `json:"id"`
	Cases       []*Case                `json:"cases"`
	Workflows   []*CaseWorkflow        `json:"workflows"`
	Evidence    []*Evidence            `json:"evidence"`
	Status      *CaseStatus            `json:"status"`
	Config      map[string]interface{} `json:"config"`
	Performance *EnginePerformance     `json:"performance"`
}

type ThreatHypothesis struct {
	ID         string    `json:"id"`
	Text       string    `json:"text"`
	Category   string    `json:"category"`
	Confidence float64   `json:"confidence"`
	Evidence   []string  `json:"evidence"`
	Status     string    `json:"status"`
	Priority   string    `json:"priority"`
	Hunter     string    `json:"hunter"`
	Created    time.Time `json:"created"`
	Updated    time.Time `json:"updated"`
}

type ThreatFinding struct {
	ID          string    `json:"id"`
	Type        string    `json:"type"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Severity    string    `json:"severity"`
	Confidence  float64   `json:"confidence"`
	Evidence    []string  `json:"evidence"`
	IOCs        []string  `json:"iocs"`
	TTPs        []string  `json:"ttps"`
	Source      string    `json:"source"`
	Hunter      string    `json:"hunter"`
	Status      string    `json:"status"`
	Created     time.Time `json:"created"`
	Updated     time.Time `json:"updated"`
}

type ThreatIndicator struct {
	ID         string                 `json:"id"`
	Type       string                 `json:"type"`
	Value      string                 `json:"value"`
	Context    map[string]interface{} `json:"context"`
	Confidence float64                `json:"confidence"`
	Source     string                 `json:"source"`
	Tags       []string               `json:"tags"`
	TTPs       []string               `json:"ttps"`
	Campaigns  []string               `json:"campaigns"`
	FirstSeen  time.Time              `json:"first_seen"`
	LastSeen   time.Time              `json:"last_seen"`
	Active     bool                   `json:"active"`
}

type ThreatCampaign struct {
	ID         string            `json:"id"`
	Name       string            `json:"name"`
	Group      string            `json:"group"`
	Objectives []string          `json:"objectives"`
	TTPs       []string          `json:"ttps"`
	IOCs       []string          `json:"iocs"`
	Targets    []string          `json:"targets"`
	Timeline   *CampaignTimeline `json:"timeline"`
	Status     string            `json:"status"`
	Confidence float64           `json:"confidence"`
	Active     bool              `json:"active"`
	Created    time.Time         `json:"created"`
	Updated    time.Time         `json:"updated"`
}

type ThreatImpact struct {
	ID           string        `json:"id"`
	Type         string        `json:"type"`
	Scope        string        `json:"scope"`
	Severity     string        `json:"severity"`
	Financial    float64       `json:"financial"`
	Operational  string        `json:"operational"`
	Strategic    string        `json:"strategic"`
	Reputational string        `json:"reputational"`
	Assets       []string      `json:"assets"`
	Services     []string      `json:"services"`
	Duration     time.Duration `json:"duration"`
	Calculated   time.Time     `json:"calculated"`
}

// Support types for the above engines
type ForensicTool struct {
	ID           string                 `json:"id"`
	Name         string                 `json:"name"`
	Type         string                 `json:"type"`
	Version      string                 `json:"version"`
	Capabilities []string               `json:"capabilities"`
	Config       map[string]interface{} `json:"config"`
}

type ForensicAnalysis struct {
	ID         string                 `json:"id"`
	Type       string                 `json:"type"`
	Tool       string                 `json:"tool"`
	Target     string                 `json:"target"`
	Results    map[string]interface{} `json:"results"`
	Artifacts  []string               `json:"artifacts"`
	Timeline   []time.Time            `json:"timeline"`
	Confidence float64                `json:"confidence"`
	Completed  time.Time              `json:"completed"`
}

type RootCause struct {
	ID           string    `json:"id"`
	Type         string    `json:"type"`
	Description  string    `json:"description"`
	Likelihood   float64   `json:"likelihood"`
	Impact       float64   `json:"impact"`
	Evidence     []string  `json:"evidence"`
	Contributing []string  `json:"contributing"`
	Identified   time.Time `json:"identified"`
}

type CauseAnalysis struct {
	CauseID    string                 `json:"cause_id"`
	Method     string                 `json:"method"`
	Results    map[string]interface{} `json:"results"`
	Confidence float64                `json:"confidence"`
	Timeline   []time.Time            `json:"timeline"`
	Analyst    string                 `json:"analyst"`
	Completed  time.Time              `json:"completed"`
}

type CauseTree struct {
	Root        *RootCause     `json:"root"`
	Branches    []*CauseBranch `json:"branches"`
	Depth       int            `json:"depth"`
	Probability float64        `json:"probability"`
	Updated     time.Time      `json:"updated"`
}

type CauseBranch struct {
	Cause       *RootCause     `json:"cause"`
	Children    []*CauseBranch `json:"children"`
	Probability float64        `json:"probability"`
	Weight      float64        `json:"weight"`
}

type Impact struct {
	ID          string        `json:"id"`
	Type        string        `json:"type"`
	Category    string        `json:"category"`
	Asset       string        `json:"asset"`
	Service     string        `json:"service"`
	Severity    string        `json:"severity"`
	Financial   float64       `json:"financial"`
	Operational string        `json:"operational"`
	Duration    time.Duration `json:"duration"`
	Assessed    time.Time     `json:"assessed"`
}

type ImpactResult struct {
	ImpactID   string             `json:"impact_id"`
	Score      float64            `json:"score"`
	Level      string             `json:"level"`
	Factors    map[string]float64 `json:"factors"`
	Mitigation []string           `json:"mitigation"`
	Assessor   string             `json:"assessor"`
	Timestamp  time.Time          `json:"timestamp"`
}

type ImpactMatrix struct {
	Categories []string               `json:"categories"`
	Levels     []string               `json:"levels"`
	Thresholds map[string]float64     `json:"thresholds"`
	Colors     map[string]string      `json:"colors"`
	Actions    map[string][]string    `json:"actions"`
	Config     map[string]interface{} `json:"config"`
}

type RemediationPlan struct {
	ID          string               `json:"id"`
	Name        string               `json:"name"`
	Description string               `json:"description"`
	Threat      string               `json:"threat"`
	Actions     []*RemediationAction `json:"actions"`
	Priority    string               `json:"priority"`
	Timeline    time.Duration        `json:"timeline"`
	Status      string               `json:"status"`
	Created     time.Time            `json:"created"`
	Updated     time.Time            `json:"updated"`
}

type RemediationAction struct {
	ID           string                 `json:"id"`
	Type         string                 `json:"type"`
	Name         string                 `json:"name"`
	Description  string                 `json:"description"`
	Handler      string                 `json:"handler"`
	Parameters   map[string]interface{} `json:"parameters"`
	Dependencies []string               `json:"dependencies"`
	Timeline     time.Duration          `json:"timeline"`
	Status       string                 `json:"status"`
	Automated    bool                   `json:"automated"`
}

type RemediationScheduler struct {
	Schedule  string                 `json:"schedule"`
	Queue     []*RemediationPlan     `json:"queue"`
	Active    []*RemediationPlan     `json:"active"`
	Completed []*RemediationPlan     `json:"completed"`
	Config    map[string]interface{} `json:"config"`
}

type Case struct {
	ID          string     `json:"id"`
	Title       string     `json:"title"`
	Description string     `json:"description"`
	Type        string     `json:"type"`
	Priority    string     `json:"priority"`
	Status      string     `json:"status"`
	Assignee    string     `json:"assignee"`
	Evidence    []string   `json:"evidence"`
	Findings    []string   `json:"findings"`
	Tags        []string   `json:"tags"`
	Created     time.Time  `json:"created"`
	Updated     time.Time  `json:"updated"`
	Closed      *time.Time `json:"closed"`
}

type CaseWorkflow struct {
	ID       string      `json:"id"`
	CaseID   string      `json:"case_id"`
	Name     string      `json:"name"`
	Steps    []*CaseStep `json:"steps"`
	Status   string      `json:"status"`
	Progress float64     `json:"progress"`
	Started  time.Time   `json:"started"`
	Updated  time.Time   `json:"updated"`
}

type CaseStep struct {
	ID         string                 `json:"id"`
	Name       string                 `json:"name"`
	Type       string                 `json:"type"`
	Action     string                 `json:"action"`
	Parameters map[string]interface{} `json:"parameters"`
	Status     string                 `json:"status"`
	Assignee   string                 `json:"assignee"`
	Completed  *time.Time             `json:"completed"`
}

type CaseStatus struct {
	Total      int            `json:"total"`
	Open       int            `json:"open"`
	InProgress int            `json:"in_progress"`
	Closed     int            `json:"closed"`
	ByPriority map[string]int `json:"by_priority"`
	ByType     map[string]int `json:"by_type"`
	ByAssignee map[string]int `json:"by_assignee"`
	Updated    time.Time      `json:"updated"`
}

// Final remaining missing hunting artifact and auxiliary types
type HuntArtifact struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Location    string                 `json:"location"`
	Hash        string                 `json:"hash"`
	Size        int64                  `json:"size"`
	Metadata    map[string]interface{} `json:"metadata"`
	Tags        []string               `json:"tags"`
	Hunter      string                 `json:"hunter"`
	Created     time.Time              `json:"created"`
	Updated     time.Time              `json:"updated"`
}

type HuntTimeline struct {
	ID          string           `json:"id"`
	HuntID      string           `json:"hunt_id"`
	Name        string           `json:"name"`
	Description string           `json:"description"`
	Events      []*TimelineEvent `json:"events"`
	Start       time.Time        `json:"start"`
	End         *time.Time       `json:"end"`
	Duration    *time.Duration   `json:"duration"`
	Hunter      string           `json:"hunter"`
	Created     time.Time        `json:"created"`
	Updated     time.Time        `json:"updated"`
}

type Collaborator struct {
	ID           string       `json:"id"`
	Name         string       `json:"name"`
	Role         string       `json:"role"`
	Organization string       `json:"organization"`
	Skills       []string     `json:"skills"`
	Contact      *ContactInfo `json:"contact"`
	Availability string       `json:"availability"`
	Active       bool         `json:"active"`
	Joined       time.Time    `json:"joined"`
}

type ExternalReference struct {
	ID          string    `json:"id"`
	Type        string    `json:"type"`
	Title       string    `json:"title"`
	URL         string    `json:"url"`
	Description string    `json:"description"`
	Source      string    `json:"source"`
	Reliability float64   `json:"reliability"`
	Relevance   float64   `json:"relevance"`
	Tags        []string  `json:"tags"`
	Created     time.Time `json:"created"`
	Accessed    time.Time `json:"accessed"`
}

type DataRequirement struct {
	ID          string        `json:"id"`
	Type        string        `json:"type"`
	Name        string        `json:"name"`
	Description string        `json:"description"`
	Source      string        `json:"source"`
	Format      string        `json:"format"`
	Volume      string        `json:"volume"`
	Retention   time.Duration `json:"retention"`
	Frequency   string        `json:"frequency"`
	Critical    bool          `json:"critical"`
	Status      string        `json:"status"`
	Hunter      string        `json:"hunter"`
	Required    time.Time     `json:"required"`
}

type ExpectedIndicator struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"`
	Value       string                 `json:"value"`
	Description string                 `json:"description"`
	Context     map[string]interface{} `json:"context"`
	Confidence  float64                `json:"confidence"`
	Source      string                 `json:"source"`
	TTPs        []string               `json:"ttps"`
	Hunter      string                 `json:"hunter"`
	Expected    time.Time              `json:"expected"`
	Found       *time.Time             `json:"found"`
	Status      string                 `json:"status"`
}

type SuccessCriterion struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Type        string    `json:"type"`
	Metric      string    `json:"metric"`
	Target      float64   `json:"target"`
	Current     float64   `json:"current"`
	Unit        string    `json:"unit"`
	Weight      float64   `json:"weight"`
	Critical    bool      `json:"critical"`
	Status      string    `json:"status"`
	Hunter      string    `json:"hunter"`
	Updated     time.Time `json:"updated"`
}

type RiskFactor struct {
	ID          string    `json:"id"`
	Type        string    `json:"type"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Category    string    `json:"category"`
	Likelihood  float64   `json:"likelihood"`
	Impact      float64   `json:"impact"`
	Risk        float64   `json:"risk"`
	Mitigation  []string  `json:"mitigation"`
	Owner       string    `json:"owner"`
	Status      string    `json:"status"`
	Identified  time.Time `json:"identified"`
	Updated     time.Time `json:"updated"`
}

type MITREMapping struct {
	ID          string    `json:"id"`
	TacticID    string    `json:"tactic_id"`
	TechniqueID string    `json:"technique_id"`
	ProcedureID string    `json:"procedure_id"`
	Description string    `json:"description"`
	IOCs        []string  `json:"iocs"`
	Confidence  float64   `json:"confidence"`
	Source      string    `json:"source"`
	Hunter      string    `json:"hunter"`
	Mapped      time.Time `json:"mapped"`
	Updated     time.Time `json:"updated"`
}

type ThreatModel struct {
	ID              string            `json:"id"`
	Name            string            `json:"name"`
	Description     string            `json:"description"`
	Version         string            `json:"version"`
	Framework       string            `json:"framework"`
	Assets          []*Asset          `json:"assets"`
	Threats         []*ThreatInfo     `json:"threats"`
	Vulnerabilities []*Vulnerability  `json:"vulnerabilities"`
	Controls        []*Control        `json:"controls"`
	Risks           []*RiskAssessment `json:"risks"`
	Author          string            `json:"author"`
	Created         time.Time         `json:"created"`
	Updated         time.Time         `json:"updated"`
}

// Support types for threat modeling
type Vulnerability struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Type        string    `json:"type"`
	CVEID       string    `json:"cve_id"`
	Severity    string    `json:"severity"`
	Score       float64   `json:"score"`
	Vector      string    `json:"vector"`
	Assets      []string  `json:"assets"`
	Threats     []string  `json:"threats"`
	Exploitable bool      `json:"exploitable"`
	Discovered  time.Time `json:"discovered"`
	Updated     time.Time `json:"updated"`
}

// Final hunt execution and finding types
type HuntPhase struct {
	ID          string           `json:"id"`
	Name        string           `json:"name"`
	Description string           `json:"description"`
	Order       int              `json:"order"`
	Status      string           `json:"status"`
	Techniques  []*HuntTechnique `json:"techniques"`
	Queries     []*HuntQuery     `json:"queries"`
	Analytics   []*HuntAnalytic  `json:"analytics"`
	Duration    time.Duration    `json:"duration"`
	Started     *time.Time       `json:"started"`
	Completed   *time.Time       `json:"completed"`
	Hunter      string           `json:"hunter"`
}

type HuntTechnique struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Type        string    `json:"type"`
	MITRE       string    `json:"mitre"`
	Tools       []string  `json:"tools"`
	Queries     []string  `json:"queries"`
	IOCs        []string  `json:"iocs"`
	Difficulty  string    `json:"difficulty"`
	Reliability float64   `json:"reliability"`
	Hunter      string    `json:"hunter"`
	Used        time.Time `json:"used"`
}

type HuntQuery struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Description string     `json:"description"`
	Query       string     `json:"query"`
	Language    string     `json:"language"`
	DataSource  string     `json:"data_source"`
	Category    string     `json:"category"`
	IOCs        []string   `json:"iocs"`
	TTPs        []string   `json:"ttps"`
	Results     int        `json:"results"`
	Executed    *time.Time `json:"executed"`
	Hunter      string     `json:"hunter"`
}

type HuntAnalytic struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Type        string                 `json:"type"`
	Algorithm   string                 `json:"algorithm"`
	Parameters  map[string]interface{} `json:"parameters"`
	DataSources []string               `json:"data_sources"`
	Threshold   float64                `json:"threshold"`
	Confidence  float64                `json:"confidence"`
	Results     []*AnalyticResult      `json:"results"`
	Hunter      string                 `json:"hunter"`
	Executed    time.Time              `json:"executed"`
}

type AnalyticResult struct {
	ID         string                 `json:"id"`
	AnalyticID string                 `json:"analytic_id"`
	Score      float64                `json:"score"`
	Confidence float64                `json:"confidence"`
	Data       map[string]interface{} `json:"data"`
	Anomalies  []string               `json:"anomalies"`
	Timestamp  time.Time              `json:"timestamp"`
}

type FindingTimeline struct {
	ID          string           `json:"id"`
	FindingID   string           `json:"finding_id"`
	Name        string           `json:"name"`
	Description string           `json:"description"`
	Events      []*TimelineEvent `json:"events"`
	Start       time.Time        `json:"start"`
	End         *time.Time       `json:"end"`
	Duration    *time.Duration   `json:"duration"`
	Hunter      string           `json:"hunter"`
	Created     time.Time        `json:"created"`
	Updated     time.Time        `json:"updated"`
}

type AffectedAsset struct {
	ID          string    `json:"id"`
	FindingID   string    `json:"finding_id"`
	AssetID     string    `json:"asset_id"`
	Name        string    `json:"name"`
	Type        string    `json:"type"`
	IP          string    `json:"ip"`
	Hostname    string    `json:"hostname"`
	OS          string    `json:"os"`
	Location    string    `json:"location"`
	Owner       string    `json:"owner"`
	Criticality string    `json:"criticality"`
	Impact      string    `json:"impact"`
	Status      string    `json:"status"`
	Compromised time.Time `json:"compromised"`
	Detected    time.Time `json:"detected"`
}

type DataExfiltration struct {
	ID          string     `json:"id"`
	FindingID   string     `json:"finding_id"`
	Type        string     `json:"type"`
	Method      string     `json:"method"`
	Source      string     `json:"source"`
	Destination string     `json:"destination"`
	DataType    string     `json:"data_type"`
	Volume      int64      `json:"volume"`
	Sensitivity string     `json:"sensitivity"`
	Encrypted   bool       `json:"encrypted"`
	Protocol    string     `json:"protocol"`
	IOCs        []string   `json:"iocs"`
	Started     time.Time  `json:"started"`
	Detected    time.Time  `json:"detected"`
	Stopped     *time.Time `json:"stopped"`
}

type LateralMovement struct {
	ID          string    `json:"id"`
	FindingID   string    `json:"finding_id"`
	Type        string    `json:"type"`
	Technique   string    `json:"technique"`
	MITRE       string    `json:"mitre"`
	Source      string    `json:"source"`
	Target      string    `json:"target"`
	Method      string    `json:"method"`
	Tool        string    `json:"tool"`
	Credentials string    `json:"credentials"`
	Success     bool      `json:"success"`
	IOCs        []string  `json:"iocs"`
	Attempted   time.Time `json:"attempted"`
	Detected    time.Time `json:"detected"`
}

type Persistence struct {
	ID          string    `json:"id"`
	FindingID   string    `json:"finding_id"`
	Type        string    `json:"type"`
	Technique   string    `json:"technique"`
	MITRE       string    `json:"mitre"`
	Asset       string    `json:"asset"`
	Method      string    `json:"method"`
	Location    string    `json:"location"`
	Artifact    string    `json:"artifact"`
	Trigger     string    `json:"trigger"`
	Persistence bool      `json:"persistence"`
	IOCs        []string  `json:"iocs"`
	Established time.Time `json:"established"`
	Detected    time.Time `json:"detected"`
}

type PrivilegeEscalation struct {
	ID            string    `json:"id"`
	FindingID     string    `json:"finding_id"`
	Type          string    `json:"type"`
	Technique     string    `json:"technique"`
	MITRE         string    `json:"mitre"`
	Asset         string    `json:"asset"`
	Method        string    `json:"method"`
	Vulnerability string    `json:"vulnerability"`
	FromPrivilege string    `json:"from_privilege"`
	ToPrivilege   string    `json:"to_privilege"`
	Tool          string    `json:"tool"`
	Success       bool      `json:"success"`
	IOCs          []string  `json:"iocs"`
	Attempted     time.Time `json:"attempted"`
	Detected      time.Time `json:"detected"`
}

// Final set of MITRE tactics and response types
type DefenseEvasion struct {
	ID        string    `json:"id"`
	FindingID string    `json:"finding_id"`
	Type      string    `json:"type"`
	Technique string    `json:"technique"`
	MITRE     string    `json:"mitre"`
	Asset     string    `json:"asset"`
	Method    string    `json:"method"`
	Tool      string    `json:"tool"`
	Evasion   string    `json:"evasion"`
	Detection string    `json:"detection"`
	Success   bool      `json:"success"`
	IOCs      []string  `json:"iocs"`
	Attempted time.Time `json:"attempted"`
	Detected  time.Time `json:"detected"`
}

type CommandAndControl struct {
	ID          string                 `json:"id"`
	FindingID   string                 `json:"finding_id"`
	Type        string                 `json:"type"`
	Technique   string                 `json:"technique"`
	MITRE       string                 `json:"mitre"`
	Asset       string                 `json:"asset"`
	Server      string                 `json:"server"`
	Protocol    string                 `json:"protocol"`
	Port        int                    `json:"port"`
	Encryption  bool                   `json:"encryption"`
	Frequency   string                 `json:"frequency"`
	Data        map[string]interface{} `json:"data"`
	IOCs        []string               `json:"iocs"`
	Established time.Time              `json:"established"`
	Detected    time.Time              `json:"detected"`
	Terminated  *time.Time             `json:"terminated"`
}

type RemediationStep struct {
	ID           string                 `json:"id"`
	PlanID       string                 `json:"plan_id"`
	Name         string                 `json:"name"`
	Description  string                 `json:"description"`
	Type         string                 `json:"type"`
	Order        int                    `json:"order"`
	Action       string                 `json:"action"`
	Parameters   map[string]interface{} `json:"parameters"`
	Dependencies []string               `json:"dependencies"`
	Automated    bool                   `json:"automated"`
	Status       string                 `json:"status"`
	Assignee     string                 `json:"assignee"`
	Started      *time.Time             `json:"started"`
	Completed    *time.Time             `json:"completed"`
	Duration     *time.Duration         `json:"duration"`
}

type ContainmentAction struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Target      string                 `json:"target"`
	Method      string                 `json:"method"`
	Parameters  map[string]interface{} `json:"parameters"`
	Impact      string                 `json:"impact"`
	Reversible  bool                   `json:"reversible"`
	Automated   bool                   `json:"automated"`
	Status      string                 `json:"status"`
	Executed    *time.Time             `json:"executed"`
	Executor    string                 `json:"executor"`
}

type EradicationAction struct {
	ID           string                 `json:"id"`
	Type         string                 `json:"type"`
	Name         string                 `json:"name"`
	Description  string                 `json:"description"`
	Target       string                 `json:"target"`
	Method       string                 `json:"method"`
	Parameters   map[string]interface{} `json:"parameters"`
	Scope        string                 `json:"scope"`
	Verification string                 `json:"verification"`
	Automated    bool                   `json:"automated"`
	Status       string                 `json:"status"`
	Executed     *time.Time             `json:"executed"`
	Executor     string                 `json:"executor"`
}

type RecoveryAction struct {
	ID           string                 `json:"id"`
	Type         string                 `json:"type"`
	Name         string                 `json:"name"`
	Description  string                 `json:"description"`
	Target       string                 `json:"target"`
	Method       string                 `json:"method"`
	Parameters   map[string]interface{} `json:"parameters"`
	Priority     string                 `json:"priority"`
	Dependencies []string               `json:"dependencies"`
	Verification string                 `json:"verification"`
	Automated    bool                   `json:"automated"`
	Status       string                 `json:"status"`
	Executed     *time.Time             `json:"executed"`
	Executor     string                 `json:"executor"`
}

type GeographicContext struct {
	ID           string             `json:"id"`
	FindingID    string             `json:"finding_id"`
	Country      string             `json:"country"`
	Region       string             `json:"region"`
	City         string             `json:"city"`
	Coordinates  map[string]float64 `json:"coordinates"`
	Timezone     string             `json:"timezone"`
	ISP          string             `json:"isp"`
	ASN          string             `json:"asn"`
	Reputation   float64            `json:"reputation"`
	ThreatLevel  string             `json:"threat_level"`
	Restrictions []string           `json:"restrictions"`
	Updated      time.Time          `json:"updated"`
}

type IndustryContext struct {
	ID          string    `json:"id"`
	FindingID   string    `json:"finding_id"`
	Industry    string    `json:"industry"`
	Sector      string    `json:"sector"`
	SubSector   string    `json:"sub_sector"`
	ThreatLevel string    `json:"threat_level"`
	Targeting   []string  `json:"targeting"`
	Campaigns   []string  `json:"campaigns"`
	Actors      []string  `json:"actors"`
	TTPs        []string  `json:"ttps"`
	Relevance   float64   `json:"relevance"`
	Updated     time.Time `json:"updated"`
}

type RegulatoryImpact struct {
	ID          string     `json:"id"`
	FindingID   string     `json:"finding_id"`
	Framework   string     `json:"framework"`
	Regulation  string     `json:"regulation"`
	Requirement string     `json:"requirement"`
	Compliance  string     `json:"compliance"`
	Impact      string     `json:"impact"`
	Penalties   []string   `json:"penalties"`
	Reporting   bool       `json:"reporting"`
	Deadline    *time.Time `json:"deadline"`
	Status      string     `json:"status"`
	Owner       string     `json:"owner"`
	Updated     time.Time  `json:"updated"`
}

type ForensicArtifact struct {
	ID          string                 `json:"id"`
	FindingID   string                 `json:"finding_id"`
	Type        string                 `json:"type"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Location    string                 `json:"location"`
	Hash        string                 `json:"hash"`
	Size        int64                  `json:"size"`
	Created     time.Time              `json:"created"`
	Modified    time.Time              `json:"modified"`
	Accessed    time.Time              `json:"accessed"`
	Metadata    map[string]interface{} `json:"metadata"`
	Chain       string                 `json:"chain"`
	Integrity   bool                   `json:"integrity"`
	Relevance   float64                `json:"relevance"`
	Analyst     string                 `json:"analyst"`
	Collected   time.Time              `json:"collected"`
}

// Investigation and incident response types
type Investigator struct {
	ID             string            `json:"id"`
	Name           string            `json:"name"`
	Email          string            `json:"email"`
	Role           string            `json:"role"`
	Department     string            `json:"department"`
	Certifications []string          `json:"certifications"`
	Specialties    []string          `json:"specialties"`
	Level          string            `json:"level"`
	Active         bool              `json:"active"`
	Assigned       []string          `json:"assigned"`
	Workload       int               `json:"workload"`
	Contact        map[string]string `json:"contact"`
	Timezone       string            `json:"timezone"`
	Available      bool              `json:"available"`
	LastActivity   time.Time         `json:"last_activity"`
}

type TriggerEvent struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"`
	Source      string                 `json:"source"`
	Description string                 `json:"description"`
	Severity    string                 `json:"severity"`
	Trigger     string                 `json:"trigger"`
	Conditions  map[string]interface{} `json:"conditions"`
	Threshold   map[string]interface{} `json:"threshold"`
	Context     map[string]interface{} `json:"context"`
	Related     []string               `json:"related"`
	Timestamp   time.Time              `json:"timestamp"`
	Processed   bool                   `json:"processed"`
	Response    string                 `json:"response"`
}

type Interview struct {
	ID          string         `json:"id"`
	CaseID      string         `json:"case_id"`
	Interviewer string         `json:"interviewer"`
	Interviewee string         `json:"interviewee"`
	Type        string         `json:"type"`
	Purpose     string         `json:"purpose"`
	Method      string         `json:"method"`
	Location    string         `json:"location"`
	Questions   []string       `json:"questions"`
	Responses   []string       `json:"responses"`
	Notes       string         `json:"notes"`
	Recording   bool           `json:"recording"`
	Transcript  string         `json:"transcript"`
	Scheduled   time.Time      `json:"scheduled"`
	Conducted   *time.Time     `json:"conducted"`
	Duration    *time.Duration `json:"duration"`
}

type DataBreach struct {
	ID          string         `json:"id"`
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Type        string         `json:"type"`
	Severity    string         `json:"severity"`
	Scope       string         `json:"scope"`
	Systems     []string       `json:"systems"`
	DataTypes   []string       `json:"data_types"`
	Records     int64          `json:"records"`
	Individuals int64          `json:"individuals"`
	Vector      string         `json:"vector"`
	Method      string         `json:"method"`
	Actor       string         `json:"actor"`
	Discovered  time.Time      `json:"discovered"`
	Occurred    time.Time      `json:"occurred"`
	Contained   *time.Time     `json:"contained"`
	Duration    *time.Duration `json:"duration"`
	Cost        float64        `json:"cost"`
	Status      string         `json:"status"`
}

type RegulatoryObligation struct {
	ID           string        `json:"id"`
	BreachID     string        `json:"breach_id"`
	Framework    string        `json:"framework"`
	Regulation   string        `json:"regulation"`
	Jurisdiction string        `json:"jurisdiction"`
	Requirement  string        `json:"requirement"`
	Timeframe    time.Duration `json:"timeframe"`
	Notification bool          `json:"notification"`
	Authority    string        `json:"authority"`
	Individual   bool          `json:"individual"`
	Public       bool          `json:"public"`
	Penalties    []string      `json:"penalties"`
	Deadline     time.Time     `json:"deadline"`
	Status       string        `json:"status"`
	Completed    *time.Time    `json:"completed"`
	Evidence     []string      `json:"evidence"`
}

type LegalImplications struct {
	ID           string             `json:"id"`
	BreachID     string             `json:"breach_id"`
	Type         string             `json:"type"`
	Jurisdiction string             `json:"jurisdiction"`
	Law          string             `json:"law"`
	Statute      string             `json:"statute"`
	Liability    string             `json:"liability"`
	Exposure     string             `json:"exposure"`
	Penalties    []string           `json:"penalties"`
	Damages      map[string]float64 `json:"damages"`
	Litigation   bool               `json:"litigation"`
	Settlement   float64            `json:"settlement"`
	Insurance    bool               `json:"insurance"`
	Coverage     float64            `json:"coverage"`
	Counsel      string             `json:"counsel"`
	Status       string             `json:"status"`
	Updated      time.Time          `json:"updated"`
}

type LessonLearned struct {
	ID              string     `json:"id"`
	CaseID          string     `json:"case_id"`
	Category        string     `json:"category"`
	Type            string     `json:"type"`
	Title           string     `json:"title"`
	Description     string     `json:"description"`
	Impact          string     `json:"impact"`
	Root            string     `json:"root"`
	Prevention      string     `json:"prevention"`
	Detection       string     `json:"detection"`
	Response        string     `json:"response"`
	Recovery        string     `json:"recovery"`
	Recommendations []string   `json:"recommendations"`
	Actions         []string   `json:"actions"`
	Owner           string     `json:"owner"`
	Priority        string     `json:"priority"`
	Status          string     `json:"status"`
	Created         time.Time  `json:"created"`
	Reviewed        *time.Time `json:"reviewed"`
}

type InvestigationReport struct {
	ID              string     `json:"id"`
	CaseID          string     `json:"case_id"`
	Type            string     `json:"type"`
	Title           string     `json:"title"`
	Summary         string     `json:"summary"`
	Findings        []string   `json:"findings"`
	Evidence        []string   `json:"evidence"`
	Timeline        []string   `json:"timeline"`
	Impact          string     `json:"impact"`
	Root            string     `json:"root"`
	Recommendations []string   `json:"recommendations"`
	Status          string     `json:"status"`
	Author          string     `json:"author"`
	Reviewer        string     `json:"reviewer"`
	Approver        string     `json:"approver"`
	Classification  string     `json:"classification"`
	Distribution    []string   `json:"distribution"`
	Created         time.Time  `json:"created"`
	Submitted       *time.Time `json:"submitted"`
	Approved        *time.Time `json:"approved"`
	Published       *time.Time `json:"published"`
}

type PeerReview struct {
	ID              string         `json:"id"`
	ReportID        string         `json:"report_id"`
	Reviewer        string         `json:"reviewer"`
	Type            string         `json:"type"`
	Scope           string         `json:"scope"`
	Methodology     string         `json:"methodology"`
	Findings        []string       `json:"findings"`
	Comments        []string       `json:"comments"`
	Recommendations []string       `json:"recommendations"`
	Quality         string         `json:"quality"`
	Accuracy        string         `json:"accuracy"`
	Completeness    string         `json:"completeness"`
	Rating          float64        `json:"rating"`
	Status          string         `json:"status"`
	Requested       time.Time      `json:"requested"`
	Started         *time.Time     `json:"started"`
	Completed       *time.Time     `json:"completed"`
	Duration        *time.Duration `json:"duration"`
}

type ExternalConsultation struct {
	ID           string                 `json:"id"`
	CaseID       string                 `json:"case_id"`
	Type         string                 `json:"type"`
	Purpose      string                 `json:"purpose"`
	Organization string                 `json:"organization"`
	Consultant   string                 `json:"consultant"`
	Expertise    []string               `json:"expertise"`
	Scope        string                 `json:"scope"`
	Deliverables []string               `json:"deliverables"`
	Cost         float64                `json:"cost"`
	Timeline     map[string]time.Time   `json:"timeline"`
	Contract     string                 `json:"contract"`
	NDA          bool                   `json:"nda"`
	Status       string                 `json:"status"`
	Requested    time.Time              `json:"requested"`
	Started      *time.Time             `json:"started"`
	Completed    *time.Time             `json:"completed"`
	Results      map[string]interface{} `json:"results"`
}

// Final missing investigation and collaboration types
type InvestigationCollaboration struct {
	ID        string                 `json:"id"`
	CaseID    string                 `json:"case_id"`
	Type      string                 `json:"type"`
	Partners  []string               `json:"partners"`
	Agencies  []string               `json:"agencies"`
	Purpose   string                 `json:"purpose"`
	Scope     string                 `json:"scope"`
	Protocols []string               `json:"protocols"`
	Sharing   map[string]interface{} `json:"sharing"`
	Security  string                 `json:"security"`
	Status    string                 `json:"status"`
	Lead      string                 `json:"lead"`
	Started   time.Time              `json:"started"`
	Updated   time.Time              `json:"updated"`
}

type CommunicationPlan struct {
	ID           string                 `json:"id"`
	CaseID       string                 `json:"case_id"`
	Type         string                 `json:"type"`
	Stakeholders []string               `json:"stakeholders"`
	Channels     []string               `json:"channels"`
	Frequency    string                 `json:"frequency"`
	Templates    []string               `json:"templates"`
	Escalation   map[string]interface{} `json:"escalation"`
	Security     string                 `json:"security"`
	Approval     bool                   `json:"approval"`
	Status       string                 `json:"status"`
	Owner        string                 `json:"owner"`
	Created      time.Time              `json:"created"`
	Updated      time.Time              `json:"updated"`
}

type InvestigationDocumentation struct {
	ID             string    `json:"id"`
	CaseID         string    `json:"case_id"`
	Type           string    `json:"type"`
	Title          string    `json:"title"`
	Description    string    `json:"description"`
	Content        string    `json:"content"`
	Format         string    `json:"format"`
	Version        string    `json:"version"`
	Status         string    `json:"status"`
	Author         string    `json:"author"`
	Reviewer       string    `json:"reviewer"`
	Classification string    `json:"classification"`
	Tags           []string  `json:"tags"`
	References     []string  `json:"references"`
	Created        time.Time `json:"created"`
	Updated        time.Time `json:"updated"`
}

type InvestigationArchive struct {
	ID          string        `json:"id"`
	CaseID      string        `json:"case_id"`
	Type        string        `json:"type"`
	Name        string        `json:"name"`
	Description string        `json:"description"`
	Location    string        `json:"location"`
	Format      string        `json:"format"`
	Size        int64         `json:"size"`
	Hash        string        `json:"hash"`
	Encryption  bool          `json:"encryption"`
	Retention   time.Duration `json:"retention"`
	Access      []string      `json:"access"`
	Status      string        `json:"status"`
	Created     time.Time     `json:"created"`
	Archived    time.Time     `json:"archived"`
}

type HuntScope struct {
	ID          string               `json:"id"`
	Name        string               `json:"name"`
	Description string               `json:"description"`
	Environment []string             `json:"environment"`
	Assets      []string             `json:"assets"`
	Networks    []string             `json:"networks"`
	Timeframe   map[string]time.Time `json:"timeframe"`
	Exclusions  []string             `json:"exclusions"`
	Status      string               `json:"status"`
	Created     time.Time            `json:"created"`
	Updated     time.Time            `json:"updated"`
}

type Environment struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Type        string                 `json:"type"`
	Description string                 `json:"description"`
	Networks    []string               `json:"networks"`
	Assets      []string               `json:"assets"`
	Services    []string               `json:"services"`
	Policies    []string               `json:"policies"`
	Security    map[string]interface{} `json:"security"`
	Status      string                 `json:"status"`
	Created     time.Time              `json:"created"`
	Updated     time.Time              `json:"updated"`
}

type InvestigationScope struct {
	ID          string               `json:"id"`
	CaseID      string               `json:"case_id"`
	Name        string               `json:"name"`
	Description string               `json:"description"`
	Objectives  []string             `json:"objectives"`
	Assets      []string             `json:"assets"`
	Systems     []string             `json:"systems"`
	Timeframe   map[string]time.Time `json:"timeframe"`
	Limitations []string             `json:"limitations"`
	Authority   string               `json:"authority"`
	Status      string               `json:"status"`
	Created     time.Time            `json:"created"`
	Updated     time.Time            `json:"updated"`
}

type HypothesisGeneratorConfig struct {
	ID         string                 `json:"id"`
	Type       string                 `json:"type"`
	Parameters map[string]interface{} `json:"parameters"`
	Models     []string               `json:"models"`
	Algorithms []string               `json:"algorithms"`
	Thresholds map[string]float64     `json:"thresholds"`
	Status     string                 `json:"status"`
	Created    time.Time              `json:"created"`
	Updated    time.Time              `json:"updated"`
}

// Missing method for HypothesisGenerator
func (hg *HypothesisGenerator) GenerateHypothesis(ctx context.Context, request interface{}) (*ThreatHypothesis, error) {
	if request == nil {
		return nil, fmt.Errorf("request cannot be nil")
	}

	// Placeholder implementation
	return &ThreatHypothesis{
		ID:         "hyp_" + time.Now().Format("20060102150405"),
		Text:       "Generated threat hypothesis based on data analysis",
		Category:   "automated",
		Confidence: 0.7,
		Evidence:   []string{},
		Status:     "draft",
		Priority:   "medium",
		Hunter:     "ai_system",
		Created:    time.Now(),
		Updated:    time.Now(),
	}, nil
} // Missing hypothesis type
type Hypothesis struct {
	ID          string    `json:"id"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Priority    string    `json:"priority"`
	Status      string    `json:"status"`
	Evidence    []string  `json:"evidence"`
	Confidence  float64   `json:"confidence"`
	Created     time.Time `json:"created"`
	Updated     time.Time `json:"updated"`
}
