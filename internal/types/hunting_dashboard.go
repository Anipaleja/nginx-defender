package types

import (
	"time"
)

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
