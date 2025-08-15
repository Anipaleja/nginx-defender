package types

import (
	"context"
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
	IOC         string                       `json:"ioc"`
	Type        string                       `json:"type"`
	Sources     []string                     `json:"sources"`
	Reputation  float64                      `json:"reputation"`
	Tags        []string                     `json:"tags"`
	Attribution []string                     `json:"attribution"`
	Context     map[string]interface{}       `json:"context"`
}

type ThreatIntelligence struct {
	ID          string                       `json:"id"`
	Type        string                       `json:"type"`
	Value       string                       `json:"value"`
	Source      string                       `json:"source"`
	Confidence  float64                      `json:"confidence"`
	Timestamp   time.Time                    `json:"timestamp"`
	Context     map[string]interface{}       `json:"context"`
}

// Missing types for Hunting package
type HuntExecutor struct {
	ID          string                        `json:"id"`
	Name        string                        `json:"name"`
	Type        string                        `json:"type"`
	Status      string                        `json:"status"`
	Capabilities []string                     `json:"capabilities"`
	Config      map[string]interface{}       `json:"config"`
	LastActive  time.Time                    `json:"last_active"`
}

type HuntPlaybook struct {
	ID          string                        `json:"id"`
	Name        string                        `json:"name"`
	Description string                        `json:"description"`
	Category    string                        `json:"category"`
	Author      string                        `json:"author"`
	Version     string                        `json:"version"`
	Tags        []string                      `json:"tags"`
	Steps       []*PlaybookStep               `json:"steps"`
	Variables   map[string]interface{}       `json:"variables"`
	CreatedAt   time.Time                     `json:"created_at"`
	UpdatedAt   time.Time                     `json:"updated_at"`
}

type HuntAutomation struct {
	ID          string                        `json:"id"`
	Name        string                        `json:"name"`
	Type        string                        `json:"type"`
	Triggers    []*AutomationTrigger          `json:"triggers"`
	Actions     []*AutomationAction           `json:"actions"`
	Conditions  []*AutomationCondition        `json:"conditions"`
	Schedule    *Schedule                     `json:"schedule"`
	Enabled     bool                          `json:"enabled"`
	LastRun     time.Time                     `json:"last_run"`
}

type AutomationTrigger struct {
	Type        string                        `json:"type"`
	Event       string                        `json:"event"`
	Condition   string                        `json:"condition"`
	Parameters  map[string]interface{}       `json:"parameters"`
	Enabled     bool                          `json:"enabled"`
}

type AutomationAction struct {
	Type        string                        `json:"type"`
	Target      string                        `json:"target"`
	Parameters  map[string]interface{}       `json:"parameters"`
	Timeout     time.Duration                 `json:"timeout"`
	Retries     int                           `json:"retries"`
}

type AutomationCondition struct {
	Field       string                        `json:"field"`
	Operator    string                        `json:"operator"`
	Value       interface{}                   `json:"value"`
	LogicalOp   string                        `json:"logical_op"`
}

type Schedule struct {
	Type        string                        `json:"type"`
	Expression  string                        `json:"expression"`
	Timezone    string                        `json:"timezone"`
	StartTime   time.Time                     `json:"start_time"`
	EndTime     *time.Time                    `json:"end_time"`
	Enabled     bool                          `json:"enabled"`
}

type SuccessMetric struct {
	Name        string                        `json:"name"`
	Type        string                        `json:"type"`
	Target      float64                       `json:"target"`
	Current     float64                       `json:"current"`
	Unit        string                        `json:"unit"`
	Trend       string                        `json:"trend"`
	LastUpdate  time.Time                     `json:"last_update"`
}

type KillChainMapping struct {
	Phase       string                        `json:"phase"`
	Techniques  []string                      `json:"techniques"`
	Indicators  []string                      `json:"indicators"`
	Countermeasures []string                  `json:"countermeasures"`
	Confidence  float64                       `json:"confidence"`
}

type AdversaryEmulation struct {
	ID          string                        `json:"id"`
	Name        string                        `json:"name"`
	Profile     *AdversaryProfile             `json:"profile"`
	Scenarios   []*EmulationScenario          `json:"scenarios"`
	Tools       []string                      `json:"tools"`
	Status      string                        `json:"status"`
	LastRun     time.Time                     `json:"last_run"`
}

type AdversaryProfile struct {
	Name        string                        `json:"name"`
	Group       string                        `json:"group"`
	Motivation  []string                      `json:"motivation"`
	Capabilities []string                     `json:"capabilities"`
	TTPs        []*TTP                        `json:"ttps"`
	Geography   []string                      `json:"geography"`
}

type EmulationScenario struct {
	ID          string                        `json:"id"`
	Name        string                        `json:"name"`
	Description string                        `json:"description"`
	Phases      []*ScenarioPhase              `json:"phases"`
	Objectives  []string                      `json:"objectives"`
	Duration    time.Duration                 `json:"duration"`
}

type ScenarioPhase struct {
	Phase       string                        `json:"phase"`
	Techniques  []string                      `json:"techniques"`
	Tools       []string                      `json:"tools"`
	Duration    time.Duration                 `json:"duration"`
	Success     *SuccessMetric                `json:"success"`
}

type RedTeamScenario struct {
	ID          string                        `json:"id"`
	Name        string                        `json:"name"`
	Type        string                        `json:"type"`
	Objective   string                        `json:"objective"`
	Target      *Target                       `json:"target"`
	Tactics     []string                      `json:"tactics"`
	Tools       []string                      `json:"tools"`
	Timeline    *Timeline                     `json:"timeline"`
	Status      string                        `json:"status"`
}

type Target struct {
	Type        string                        `json:"type"`
	Name        string                        `json:"name"`
	IP          string                        `json:"ip"`
	Domain      string                        `json:"domain"`
	Services    []string                      `json:"services"`
	Criticality string                        `json:"criticality"`
}

type Timeline struct {
	StartTime   time.Time                     `json:"start_time"`
	EndTime     time.Time                     `json:"end_time"`
	Phases      []*TimelinePhase              `json:"phases"`
	Milestones  []*Milestone                  `json:"milestones"`
}

type TimelinePhase struct {
	Name        string                        `json:"name"`
	StartTime   time.Time                     `json:"start_time"`
	EndTime     time.Time                     `json:"end_time"`
	Activities  []string                      `json:"activities"`
	Status      string                        `json:"status"`
}

type Milestone struct {
	Name        string                        `json:"name"`
	Time        time.Time                     `json:"time"`
	Status      string                        `json:"status"`
	Description string                        `json:"description"`
}

type ThreatIntelligenceReq struct {
	Type        string                        `json:"type"`
	Priority    string                        `json:"priority"`
	Subject     string                        `json:"subject"`
	Context     string                        `json:"context"`
	Sources     []string                      `json:"sources"`
	Deadline    time.Time                     `json:"deadline"`
	Requestor   string                        `json:"requestor"`
	Status      string                        `json:"status"`
}

type CollaborationModel struct {
	Type        string                        `json:"type"`
	Members     []*TeamMember                 `json:"members"`
	Roles       map[string][]string           `json:"roles"`
	Permissions map[string][]string           `json:"permissions"`
	Communication *CommunicationSettings      `json:"communication"`
}

type TeamMember struct {
	ID          string                        `json:"id"`
	Name        string                        `json:"name"`
	Role        string                        `json:"role"`
	Skills      []string                      `json:"skills"`
	Availability string                       `json:"availability"`
	Contact     *ContactInfo                  `json:"contact"`
}

type ContactInfo struct {
	Email       string                        `json:"email"`
	Phone       string                        `json:"phone"`
	Slack       string                        `json:"slack"`
	Timezone    string                        `json:"timezone"`
}

type CommunicationSettings struct {
	Channels    []string                      `json:"channels"`
	Frequency   string                        `json:"frequency"`
	Escalation  *EscalationPolicy             `json:"escalation"`
	Notifications *NotificationSettings       `json:"notifications"`
}

type EscalationPolicy struct {
	Levels      []*EscalationLevel            `json:"levels"`
	Timeout     time.Duration                 `json:"timeout"`
	AutoEscalate bool                         `json:"auto_escalate"`
}

type EscalationLevel struct {
	Level       int                           `json:"level"`
	Recipients  []string                      `json:"recipients"`
	Timeout     time.Duration                 `json:"timeout"`
	Actions     []string                      `json:"actions"`
}

type NotificationSettings struct {
	Email       bool                          `json:"email"`
	SMS         bool                          `json:"sms"`
	Slack       bool                          `json:"slack"`
	Push        bool                          `json:"push"`
	Urgency     map[string][]string           `json:"urgency"`
}

type QualityAssurance struct {
	Reviews     []*QAReview                   `json:"reviews"`
	Checklist   []*QAItem                     `json:"checklist"`
	Standards   map[string]interface{}        `json:"standards"`
	Metrics     *QAMetrics                    `json:"metrics"`
	LastReview  time.Time                     `json:"last_review"`
}

type QAReview struct {
	ID          string                        `json:"id"`
	Type        string                        `json:"type"`
	Subject     string                        `json:"subject"`
	Reviewer    string                        `json:"reviewer"`
	Status      string                        `json:"status"`
	Findings    []*QAFinding                  `json:"findings"`
	Score       float64                       `json:"score"`
	Date        time.Time                     `json:"date"`
}

type QAFinding struct {
	Type        string                        `json:"type"`
	Severity    string                        `json:"severity"`
	Description string                        `json:"description"`
	Recommendation string                     `json:"recommendation"`
	Status      string                        `json:"status"`
}

type QAItem struct {
	ID          string                        `json:"id"`
	Category    string                        `json:"category"`
	Item        string                        `json:"item"`
	Required    bool                          `json:"required"`
	Weight      float64                       `json:"weight"`
	Status      string                        `json:"status"`
}

type QAMetrics struct {
	PassRate    float64                       `json:"pass_rate"`
	AverageScore float64                      `json:"average_score"`
	DefectRate  float64                       `json:"defect_rate"`
	CoverageRate float64                      `json:"coverage_rate"`
	LastCalculated time.Time                 `json:"last_calculated"`
}

// Missing types for Dashboard package
type DataAggregator struct {
	Functions   map[string]*AggregateFunction `json:"functions"`
	Window      *TimeWindow                   `json:"window"`
	Grouping    []string                      `json:"grouping"`
	Output      *AggregateOutput              `json:"output"`
}

type AggregateFunction struct {
	Name        string                        `json:"name"`
	Type        string                        `json:"type"`
	Field       string                        `json:"field"`
	Parameters  map[string]interface{}        `json:"parameters"`
}

type TimeWindow struct {
	Size        time.Duration                 `json:"size"`
	Slide       time.Duration                 `json:"slide"`
	Type        string                        `json:"type"`
	Alignment   string                        `json:"alignment"`
}

type AggregateOutput struct {
	Format      string                        `json:"format"`
	Destination string                        `json:"destination"`
	Frequency   time.Duration                 `json:"frequency"`
	Retention   time.Duration                 `json:"retention"`
}

type MetricCalculator struct {
	Metrics     []*MetricDefinition           `json:"metrics"`
	Calculator  *Calculator                   `json:"calculator"`
	Cache       *MetricCache                  `json:"cache"`
	Schedule    *Schedule                     `json:"schedule"`
}

type MetricDefinition struct {
	Name        string                        `json:"name"`
	Type        string                        `json:"type"`
	Formula     string                        `json:"formula"`
	Unit        string                        `json:"unit"`
	Description string                        `json:"description"`
	Tags        []string                      `json:"tags"`
}

type Calculator struct {
	Engine      string                        `json:"engine"`
	Functions   map[string]interface{}        `json:"functions"`
	Variables   map[string]interface{}        `json:"variables"`
	Precision   int                           `json:"precision"`
}

type MetricCache struct {
	Values      map[string]*MetricValue       `json:"values"`
	TTL         time.Duration                 `json:"ttl"`
	MaxSize     int                           `json:"max_size"`
	HitRate     float64                       `json:"hit_rate"`
}

type MetricValue struct {
	Value       interface{}                   `json:"value"`
	Timestamp   time.Time                     `json:"timestamp"`
	Quality     string                        `json:"quality"`
	Source      string                        `json:"source"`
}

type FilterEngine struct {
	Filters     []*Filter                     `json:"filters"`
	Rules       []*FilterRule                 `json:"rules"`
	Engine      string                        `json:"engine"`
	Performance *FilterPerformance            `json:"performance"`
}

type Filter struct {
	ID          string                        `json:"id"`
	Name        string                        `json:"name"`
	Type        string                        `json:"type"`
	Expression  string                        `json:"expression"`
	Enabled     bool                          `json:"enabled"`
	Priority    int                           `json:"priority"`
}

type FilterRule struct {
	Field       string                        `json:"field"`
	Operator    string                        `json:"operator"`
	Value       interface{}                   `json:"value"`
	Action      string                        `json:"action"`
	Weight      float64                       `json:"weight"`
}

type FilterPerformance struct {
	ProcessedCount uint64                     `json:"processed_count"`
	FilteredCount  uint64                     `json:"filtered_count"`
	AverageLatency time.Duration              `json:"average_latency"`
	Throughput    float64                     `json:"throughput"`
}

type TransformationEngine struct {
	Transformations []*Transformation          `json:"transformations"`
	Pipeline       *TransformPipeline          `json:"pipeline"`
	Schema         *TransformSchema            `json:"schema"`
	Performance    *TransformPerformance       `json:"performance"`
}

type Transformation struct {
	ID          string                        `json:"id"`
	Name        string                        `json:"name"`
	Type        string                        `json:"type"`
	Input       string                        `json:"input"`
	Output      string                        `json:"output"`
	Function    string                        `json:"function"`
	Parameters  map[string]interface{}        `json:"parameters"`
}

type TransformPipeline struct {
	Stages      []*TransformStage             `json:"stages"`
	Parallel    bool                          `json:"parallel"`
	ErrorPolicy string                        `json:"error_policy"`
	Timeout     time.Duration                 `json:"timeout"`
}

type TransformStage struct {
	ID            string                      `json:"id"`
	Name          string                      `json:"name"`
	Transform     *Transformation             `json:"transform"`
	Dependencies  []string                    `json:"dependencies"`
	Condition     string                      `json:"condition"`
}

type TransformSchema struct {
	InputSchema   map[string]interface{}      `json:"input_schema"`
	OutputSchema  map[string]interface{}      `json:"output_schema"`
	Validation    bool                        `json:"validation"`
	ErrorHandling string                      `json:"error_handling"`
}

type TransformPerformance struct {
	TransformedCount uint64                   `json:"transformed_count"`
	ErrorCount      uint64                    `json:"error_count"`
	AverageLatency  time.Duration             `json:"average_latency"`
	Throughput      float64                   `json:"throughput"`
}

type BufferManager struct {
	Buffers     map[string]*Buffer            `json:"buffers"`
	Policy      *BufferPolicy                 `json:"policy"`
	Monitor     *BufferMonitor                `json:"monitor"`
	Stats       *BufferStats                  `json:"stats"`
}

type Buffer struct {
	ID          string                        `json:"id"`
	Type        string                        `json:"type"`
	Size        int                           `json:"size"`
	MaxSize     int                           `json:"max_size"`
	Items       []interface{}                 `json:"items"`
	Watermarks  *BufferWatermarks             `json:"watermarks"`
}

type BufferPolicy struct {
	OverflowPolicy  string                    `json:"overflow_policy"`
	EvictionPolicy  string                    `json:"eviction_policy"`
	CompressionPolicy string                  `json:"compression_policy"`
	PersistencePolicy string                  `json:"persistence_policy"`
}

type BufferWatermarks struct {
	Low         int                           `json:"low"`
	High        int                           `json:"high"`
	Critical    int                           `json:"critical"`
}

type BufferMonitor struct {
	Enabled     bool                          `json:"enabled"`
	Interval    time.Duration                 `json:"interval"`
	Alerts      []*BufferAlert                `json:"alerts"`
	Metrics     []string                      `json:"metrics"`
}

type BufferAlert struct {
	Type        string                        `json:"type"`
	Condition   string                        `json:"condition"`
	Threshold   float64                       `json:"threshold"`
	Action      string                        `json:"action"`
	Enabled     bool                          `json:"enabled"`
}

type BufferStats struct {
	TotalWrites    uint64                     `json:"total_writes"`
	TotalReads     uint64                     `json:"total_reads"`
	Overflows      uint64                     `json:"overflows"`
	Evictions      uint64                     `json:"evictions"`
	AverageLatency time.Duration              `json:"average_latency"`
	Utilization    float64                    `json:"utilization"`
}

type CompressionEngine struct {
	Algorithm   string                        `json:"algorithm"`
	Level       int                           `json:"level"`
	Dictionary  []byte                        `json:"dictionary"`
	Stats       *CompressionStats             `json:"stats"`
	Config      *CompressionConfig            `json:"config"`
}

type CompressionStats struct {
	CompressedBytes   uint64                  `json:"compressed_bytes"`
	UncompressedBytes uint64                  `json:"uncompressed_bytes"`
	CompressionRatio  float64                 `json:"compression_ratio"`
	AverageLatency    time.Duration           `json:"average_latency"`
	Throughput        float64                 `json:"throughput"`
}

type CompressionConfig struct {
	BlockSize       int                       `json:"block_size"`
	WindowSize      int                       `json:"window_size"`
	MinCompression  float64                   `json:"min_compression"`
	MaxLatency      time.Duration             `json:"max_latency"`
}

type TimeSeriesAnalyzer struct {
	Models      []*TimeSeriesModel            `json:"models"`
	Algorithms  []string                      `json:"algorithms"`
	Features    *TimeSeriesFeatures           `json:"features"`
	Forecaster  *Forecaster                   `json:"forecaster"`
}

type TimeSeriesFeatures struct {
	Trend       bool                          `json:"trend"`
	Seasonality bool                          `json:"seasonality"`
	Noise       bool                          `json:"noise"`
	Outliers    bool                          `json:"outliers"`
	Patterns    []string                      `json:"patterns"`
}

type Forecaster struct {
	Algorithm   string                        `json:"algorithm"`
	Horizon     int                           `json:"horizon"`
	Confidence  float64                       `json:"confidence"`
	Model       Model                         `json:"model"`
	Parameters  map[string]interface{}        `json:"parameters"`
}

type StatisticalAnalyzer struct {
	Statistics  []*StatisticDefinition        `json:"statistics"`
	Tests       []*StatisticalTest            `json:"tests"`
	Distribution *DistributionAnalyzer        `json:"distribution"`
	Correlation *CorrelationAnalyzer          `json:"correlation"`
}

type StatisticDefinition struct {
	Name        string                        `json:"name"`
	Type        string                        `json:"type"`
	Function    string                        `json:"function"`
	Parameters  map[string]interface{}        `json:"parameters"`
	Description string                        `json:"description"`
}

type StatisticalTest struct {
	Name        string                        `json:"name"`
	Type        string                        `json:"type"`
	Hypothesis  string                        `json:"hypothesis"`
	Significance float64                      `json:"significance"`
	Result      *TestResult                   `json:"result"`
}

type TestResult struct {
	Statistic   float64                       `json:"statistic"`
	PValue      float64                       `json:"p_value"`
	Critical    float64                       `json:"critical"`
	Conclusion  string                        `json:"conclusion"`
	Confidence  float64                       `json:"confidence"`
}

type DistributionAnalyzer struct {
	Type        string                        `json:"type"`
	Parameters  map[string]float64            `json:"parameters"`
	Goodness    *GoodnessOfFit                `json:"goodness"`
	Quantiles   map[string]float64            `json:"quantiles"`
}

type GoodnessOfFit struct {
	Test        string                        `json:"test"`
	Statistic   float64                       `json:"statistic"`
	PValue      float64                       `json:"p_value"`
	Hypothesis  string                        `json:"hypothesis"`
}

type CorrelationAnalyzer struct {
	Method      string                        `json:"method"`
	Matrix      [][]float64                   `json:"matrix"`
	Threshold   float64                       `json:"threshold"`
	Significant []string                      `json:"significant"`
}

// Additional hunting types
type EvidenceCollector struct {
	Sources     map[string]*EvidenceSource   `json:"sources"`
	Artifacts   []*DigitalArtifact           `json:"artifacts"`
	Chain       *EvidenceChain               `json:"chain"`
	Config      map[string]interface{}       `json:"config"`
}

type EvidenceSource struct {
	Type        string                       `json:"type"`
	Location    string                       `json:"location"`
	Reliability float64                      `json:"reliability"`
	LastAccess  time.Time                    `json:"last_access"`
}

type DigitalArtifact struct {
	ID          string                       `json:"id"`
	Type        string                       `json:"type"`
	Hash        string                       `json:"hash"`
	Size        int64                        `json:"size"`
	Created     time.Time                    `json:"created"`
	Metadata    map[string]interface{}       `json:"metadata"`
}

type EvidenceChain struct {
	Links       []*ChainLink                 `json:"links"`
	Integrity   bool                         `json:"integrity"`
	Verified    bool                         `json:"verified"`
	Timestamp   time.Time                    `json:"timestamp"`
}

type ChainLink struct {
	Hash        string                       `json:"hash"`
	Previous    string                       `json:"previous"`
	Evidence    string                       `json:"evidence"`
	Timestamp   time.Time                    `json:"timestamp"`
}

type AttackChainAnalyzer struct {
	Chains      []*AttackChain               `json:"chains"`
	Patterns    map[string]*ChainPattern     `json:"patterns"`
	Predictor   *ChainPredictor              `json:"predictor"`
	Config      map[string]interface{}       `json:"config"`
}

type AttackChain struct {
	ID          string                       `json:"id"`
	Steps       []*AttackStep                `json:"steps"`
	Timeline    []time.Time                  `json:"timeline"`
	Confidence  float64                      `json:"confidence"`
	Complete    bool                         `json:"complete"`
}

type AttackStep struct {
	Technique   string                       `json:"technique"`
	Tool        string                       `json:"tool"`
	Target      string                       `json:"target"`
	Success     bool                         `json:"success"`
	Timestamp   time.Time                    `json:"timestamp"`
}

type ChainPattern struct {
	Sequence    []string                     `json:"sequence"`
	Frequency   int                          `json:"frequency"`
	Success     float64                      `json:"success"`
	LastSeen    time.Time                    `json:"last_seen"`
}

type ChainPredictor struct {
	Model       string                       `json:"model"`
	Accuracy    float64                      `json:"accuracy"`
	Predictions map[string]float64           `json:"predictions"`
	LastTrained time.Time                    `json:"last_trained"`
}

type MITRETacticsMapper struct {
	Tactics     map[string]*MITRETactic      `json:"tactics"`
	Techniques  map[string]*MITRETechnique   `json:"techniques"`
	Procedures  map[string]*MITREProcedure   `json:"procedures"`
	Mapping     map[string][]string          `json:"mapping"`
}

type MITRETactic struct {
	ID          string                       `json:"id"`
	Name        string                       `json:"name"`
	Description string                       `json:"description"`
	Techniques  []string                     `json:"techniques"`
}

type MITRETechnique struct {
	ID          string                       `json:"id"`
	Name        string                       `json:"name"`
	Tactic      string                       `json:"tactic"`
	Description string                       `json:"description"`
	Procedures  []string                     `json:"procedures"`
}

type MITREProcedure struct {
	ID          string                       `json:"id"`
	Name        string                       `json:"name"`
	Technique   string                       `json:"technique"`
	Description string                       `json:"description"`
	Groups      []string                     `json:"groups"`
}

type TechniqueDetector struct {
	Detectors   map[string]*Detector         `json:"detectors"`
	Rules       []*DetectionRule             `json:"rules"`
	Analytics   []*TechniqueAnalytic         `json:"analytics"`
	Config      map[string]interface{}       `json:"config"`
}

type DetectionRule struct {
	ID          string                       `json:"id"`
	Name        string                       `json:"name"`
	Logic       string                       `json:"logic"`
	Threshold   float64                      `json:"threshold"`
	Enabled     bool                         `json:"enabled"`
}

type TechniqueAnalytic struct {
	ID          string                       `json:"id"`
	Technique   string                       `json:"technique"`
	Query       string                       `json:"query"`
	Frequency   time.Duration                `json:"frequency"`
	LastRun     time.Time                    `json:"last_run"`
}

type CampaignTracker struct {
	Campaigns   map[string]*Campaign         `json:"campaigns"`
	Indicators  map[string]*CampaignIOC      `json:"indicators"`
	Timeline    *CampaignTimeline            `json:"timeline"`
	Config      map[string]interface{}       `json:"config"`
}

type Campaign struct {
	ID          string                       `json:"id"`
	Name        string                       `json:"name"`
	Group       string                       `json:"group"`
	Start       time.Time                    `json:"start"`
	End         *time.Time                   `json:"end"`
	Active      bool                         `json:"active"`
	IOCs        []string                     `json:"iocs"`
}

type CampaignIOC struct {
	Value       string                       `json:"value"`
	Type        string                       `json:"type"`
	Campaign    string                       `json:"campaign"`
	FirstSeen   time.Time                    `json:"first_seen"`
	LastSeen    time.Time                    `json:"last_seen"`
}

type CampaignTimeline struct {
	Events      []*CampaignEvent             `json:"events"`
	Phases      []*CampaignPhase             `json:"phases"`
	Duration    time.Duration                `json:"duration"`
	Updated     time.Time                    `json:"updated"`
}

type CampaignEvent struct {
	ID          string                       `json:"id"`
	Type        string                       `json:"type"`
	Description string                       `json:"description"`
	Timestamp   time.Time                    `json:"timestamp"`
	IOCs        []string                     `json:"iocs"`
}

type CampaignPhase struct {
	Name        string                       `json:"name"`
	Start       time.Time                    `json:"start"`
	End         *time.Time                   `json:"end"`
	TTPs        []string                     `json:"ttps"`
	Success     bool                         `json:"success"`
}

type ThreatActorProfiler struct {
	Profiles    map[string]*ThreatActorProfile `json:"profiles"`
	Behaviors   map[string]*ActorBehavior     `json:"behaviors"`
	Attribution *Attribution                  `json:"attribution"`
	Config      map[string]interface{}        `json:"config"`
}

type ThreatActorProfile struct {
	ID          string                       `json:"id"`
	Name        string                       `json:"name"`
	Aliases     []string                     `json:"aliases"`
	Country     string                       `json:"country"`
	Motivation  string                       `json:"motivation"`
	Sophistication string                     `json:"sophistication"`
	TTPs        []string                     `json:"ttps"`
	Campaigns   []string                     `json:"campaigns"`
}

type ActorBehavior struct {
	Pattern     string                       `json:"pattern"`
	Frequency   float64                      `json:"frequency"`
	Confidence  float64                      `json:"confidence"`
	Examples    []string                     `json:"examples"`
	LastSeen    time.Time                    `json:"last_seen"`
}

type Attribution struct {
	Confidence  float64                      `json:"confidence"`
	Factors     map[string]float64           `json:"factors"`
	Evidence    []string                     `json:"evidence"`
	Analysis    string                       `json:"analysis"`
	Updated     time.Time                    `json:"updated"`
}

type IOCManager struct {
	IOCs        map[string]*IOC              `json:"iocs"`
	Sources     []*IOCSource                 `json:"sources"`
	Enrichment  *IOCEnrichment               `json:"enrichment"`
	Analytics   *IOCAnalyzer                 `json:"analytics"`
	Config      map[string]interface{}       `json:"config"`
}

type IOCSource struct {
	Name        string                       `json:"name"`
	URL         string                       `json:"url"`
	Type        string                       `json:"type"`
	Reliability float64                      `json:"reliability"`
	LastUpdate  time.Time                    `json:"last_update"`
}

type IOCAnalyzer struct {
	Patterns    map[string]*IOCPattern       `json:"patterns"`
	Correlations []*IOCCorrelation           `json:"correlations"`
	Stats       *IOCStatistics               `json:"stats"`
	Config      map[string]interface{}       `json:"config"`
}

type IOCCorrelation struct {
	IOC1        string                       `json:"ioc1"`
	IOC2        string                       `json:"ioc2"`
	Type        string                       `json:"type"`
	Strength    float64                      `json:"strength"`
	LastSeen    time.Time                    `json:"last_seen"`
}

type IOCStatistics struct {
	Total       int                          `json:"total"`
	ByType      map[string]int               `json:"by_type"`
	BySource    map[string]int               `json:"by_source"`
	Recent      int                          `json:"recent"`
	Updated     time.Time                    `json:"updated"`
}

// Dashboard analyzer types
type TrendAnalyzer struct {
	Trends      map[string]*Trend            `json:"trends"`
	Forecasts   map[string]*Forecast         `json:"forecasts"`
	Algorithms  []string                     `json:"algorithms"`
	Config      map[string]interface{}       `json:"config"`
}

type Trend struct {
	Metric      string                       `json:"metric"`
	Direction   string                       `json:"direction"`
	Strength    float64                      `json:"strength"`
	Duration    time.Duration                `json:"duration"`
	Confidence  float64                      `json:"confidence"`
}

type Forecast struct {
	Metric      string                       `json:"metric"`
	Values      []float64                    `json:"values"`
	Timestamps  []time.Time                  `json:"timestamps"`
	Confidence  []float64                    `json:"confidence"`
	Method      string                       `json:"method"`
}

type PatternRecognition struct {
	Patterns    map[string]*Pattern          `json:"patterns"`
	Matcher     *PatternMatcher              `json:"matcher"`
	Learner     *PatternLearner              `json:"learner"`
	Config      map[string]interface{}       `json:"config"`
}

type Pattern struct {
	ID          string                       `json:"id"`
	Type        string                       `json:"type"`
	Signature   []float64                    `json:"signature"`
	Frequency   int                          `json:"frequency"`
	LastSeen    time.Time                    `json:"last_seen"`
}

type PatternMatcher struct {
	Algorithm   string                       `json:"algorithm"`
	Threshold   float64                      `json:"threshold"`
	Cache       map[string]bool              `json:"cache"`
	Stats       *MatchingStats               `json:"stats"`
}

type PatternLearner struct {
	Model       string                       `json:"model"`
	Training    bool                         `json:"training"`
	Accuracy    float64                      `json:"accuracy"`
	LastTrained time.Time                    `json:"last_trained"`
}

type MatchingStats struct {
	Matches     int                          `json:"matches"`
	FalsePos    int                          `json:"false_positives"`
	FalseNeg    int                          `json:"false_negatives"`
	Accuracy    float64                      `json:"accuracy"`
}

type BehaviorAnalyzer struct {
	Profiles    map[string]*BehaviorProfile  `json:"profiles"`
	Anomalies   []*BehaviorAnomaly           `json:"anomalies"`
	Baselines   map[string]*Baseline         `json:"baselines"`
	Config      map[string]interface{}       `json:"config"`
}

type BehaviorProfile struct {
	UserID      string                       `json:"user_id"`
	Patterns    map[string]float64           `json:"patterns"`
	LastUpdate  time.Time                    `json:"last_update"`
	Confidence  float64                      `json:"confidence"`
}

type BehaviorAnomaly struct {
	UserID      string                       `json:"user_id"`
	Type        string                       `json:"type"`
	Severity    float64                      `json:"severity"`
	Timestamp   time.Time                    `json:"timestamp"`
	Details     map[string]interface{}       `json:"details"`
}

type Baseline struct {
	Metric      string                       `json:"metric"`
	Mean        float64                      `json:"mean"`
	StdDev      float64                      `json:"std_dev"`
	Min         float64                      `json:"min"`
	Max         float64                      `json:"max"`
	Updated     time.Time                    `json:"updated"`
}

type NetworkAnalyzer struct {
	Flows       []*NetworkFlow               `json:"flows"`
	Topology    *NetworkTopology             `json:"topology"`
	Anomalies   []*NetworkAnomaly            `json:"anomalies"`
	Config      map[string]interface{}       `json:"config"`
}

type NetworkFlow struct {
	SourceIP    string                       `json:"source_ip"`
	DestIP      string                       `json:"dest_ip"`
	SourcePort  int                          `json:"source_port"`
	DestPort    int                          `json:"dest_port"`
	Protocol    string                       `json:"protocol"`
	Bytes       int64                        `json:"bytes"`
	Packets     int64                        `json:"packets"`
	Duration    time.Duration                `json:"duration"`
}

type NetworkTopology struct {
	Nodes       []*NetworkNode               `json:"nodes"`
	Edges       []*NetworkEdge               `json:"edges"`
	Subnets     []*Subnet                    `json:"subnets"`
	Updated     time.Time                    `json:"updated"`
}

type NetworkNode struct {
	IP          string                       `json:"ip"`
	Type        string                       `json:"type"`
	Role        string                       `json:"role"`
	Services    []string                     `json:"services"`
	LastSeen    time.Time                    `json:"last_seen"`
}

type NetworkEdge struct {
	Source      string                       `json:"source"`
	Dest        string                       `json:"dest"`
	Weight      float64                      `json:"weight"`
	Type        string                       `json:"type"`
}

type Subnet struct {
	CIDR        string                       `json:"cidr"`
	Name        string                       `json:"name"`
	Type        string                       `json:"type"`
	Nodes       []string                     `json:"nodes"`
}

type NetworkAnomaly struct {
	Type        string                       `json:"type"`
	Source      string                       `json:"source"`
	Dest        string                       `json:"dest"`
	Severity    float64                      `json:"severity"`
	Timestamp   time.Time                    `json:"timestamp"`
	Details     string                       `json:"details"`
}

type UserAnalyzer struct {
	Users       map[string]*UserProfile      `json:"users"`
	Sessions    map[string]*UserSession      `json:"sessions"`
	Activities  []*UserActivity              `json:"activities"`
	Config      map[string]interface{}       `json:"config"`
}

type UserProfile struct {
	ID          string                       `json:"id"`
	Username    string                       `json:"username"`
	Role        string                       `json:"role"`
	LastLogin   time.Time                    `json:"last_login"`
	Permissions []string                     `json:"permissions"`
	Risk        float64                      `json:"risk"`
}

type UserActivity struct {
	UserID      string                       `json:"user_id"`
	Action      string                       `json:"action"`
	Resource    string                       `json:"resource"`
	Result      string                       `json:"result"`
	Timestamp   time.Time                    `json:"timestamp"`
	IP          string                       `json:"ip"`
}

type AssetAnalyzer struct {
	Assets      map[string]*Asset            `json:"assets"`
	Inventory   *AssetInventory              `json:"inventory"`
	Risks       []*AssetRisk                 `json:"risks"`
	Config      map[string]interface{}       `json:"config"`
}

type Asset struct {
	ID          string                       `json:"id"`
	Name        string                       `json:"name"`
	Type        string                       `json:"type"`
	Owner       string                       `json:"owner"`
	Value       string                       `json:"value"`
	Location    string                       `json:"location"`
	LastScanned time.Time                    `json:"last_scanned"`
}

type AssetInventory struct {
	Total       int                          `json:"total"`
	ByType      map[string]int               `json:"by_type"`
	ByOwner     map[string]int               `json:"by_owner"`
	ByLocation  map[string]int               `json:"by_location"`
	Updated     time.Time                    `json:"updated"`
}

type AssetRisk struct {
	AssetID     string                       `json:"asset_id"`
	Type        string                       `json:"type"`
	Severity    string                       `json:"severity"`
	Score       float64                      `json:"score"`
	Description string                       `json:"description"`
	Timestamp   time.Time                    `json:"timestamp"`
}

type ThreatAnalyzer struct {
	Threats     map[string]*ThreatInfo       `json:"threats"`
	Intelligence *ThreatIntelligence         `json:"intelligence"`
	Predictions []*ThreatPrediction          `json:"predictions"`
	Config      map[string]interface{}       `json:"config"`
}

type ThreatInfo struct {
	ID          string                       `json:"id"`
	Name        string                       `json:"name"`
	Type        string                       `json:"type"`
	Severity    string                       `json:"severity"`
	Description string                       `json:"description"`
	TTPs        []string                     `json:"ttps"`
	IOCs        []string                     `json:"iocs"`
}

type ThreatPrediction struct {
	ThreatID    string                       `json:"threat_id"`
	Probability float64                      `json:"probability"`
	Timeframe   time.Duration                `json:"timeframe"`
	Confidence  float64                      `json:"confidence"`
	Factors     []string                     `json:"factors"`
}

type ComplianceAnalyzer struct {
	Frameworks  map[string]*ComplianceFramework `json:"frameworks"`
	Controls    map[string]*Control          `json:"controls"`
	Assessments []*ComplianceAssessment      `json:"assessments"`
	Config      map[string]interface{}       `json:"config"`
}

type ComplianceFramework struct {
	ID          string                       `json:"id"`
	Name        string                       `json:"name"`
	Version     string                       `json:"version"`
	Controls    []string                     `json:"controls"`
	Updated     time.Time                    `json:"updated"`
}

type Control struct {
	ID          string                       `json:"id"`
	Name        string                       `json:"name"`
	Description string                       `json:"description"`
	Category    string                       `json:"category"`
	Status      string                       `json:"status"`
	LastTest    time.Time                    `json:"last_test"`
}

type ComplianceAssessment struct {
	FrameworkID string                       `json:"framework_id"`
	Score       float64                      `json:"score"`
	Passed      int                          `json:"passed"`
	Failed      int                          `json:"failed"`
	Timestamp   time.Time                    `json:"timestamp"`
	Details     map[string]string            `json:"details"`
}

type BusinessImpactAnalyzer struct {
	Impacts     []*BusinessImpact            `json:"impacts"`
	Metrics     *ImpactMetrics               `json:"metrics"`
	Scenarios   []*ImpactScenario            `json:"scenarios"`
	Config      map[string]interface{}       `json:"config"`
}

type BusinessImpact struct {
	ID          string                       `json:"id"`
	Type        string                       `json:"type"`
	Asset       string                       `json:"asset"`
	Financial   float64                      `json:"financial"`
	Operational string                       `json:"operational"`
	Reputational string                      `json:"reputational"`
	Timestamp   time.Time                    `json:"timestamp"`
}

type ImpactMetrics struct {
	TotalFinancial    float64                `json:"total_financial"`
	AvgDowntime       time.Duration          `json:"avg_downtime"`
	AffectedServices  int                    `json:"affected_services"`
	CustomerImpact    float64                `json:"customer_impact"`
	Updated           time.Time              `json:"updated"`
}

type ImpactScenario struct {
	ID          string                       `json:"id"`
	Name        string                       `json:"name"`
	Likelihood  float64                      `json:"likelihood"`
	Impact      float64                      `json:"impact"`
	Risk        float64                      `json:"risk"`
	Mitigation  []string                     `json:"mitigation"`
}

type ChartRenderer struct {
	Charts      map[string]*Chart            `json:"charts"`
	Templates   map[string]*ChartTemplate    `json:"templates"`
	Config      map[string]interface{}       `json:"config"`
}

type Chart struct {
	ID          string                       `json:"id"`
	Type        string                       `json:"type"`
	Title       string                       `json:"title"`
	Data        interface{}                  `json:"data"`
	Options     map[string]interface{}       `json:"options"`
	Updated     time.Time                    `json:"updated"`
}

type ChartTemplate struct {
	ID          string                       `json:"id"`
	Name        string                       `json:"name"`
	Type        string                       `json:"type"`
	Layout      map[string]interface{}       `json:"layout"`
	DefaultOptions map[string]interface{}    `json:"default_options"`
}
