package ranges

import (
	"embed"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"sort"
	"strings"
)

//go:embed data/*.json
var rangeData embed.FS

// IPRange represents a CIDR range with metadata
type IPRange struct {
	CIDR        string            `json:"cidr"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Service     string            `json:"service"`
	Country     string            `json:"country,omitempty"`
	Tags        []string          `json:"tags,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// RangeManager manages IP ranges and provides fast lookup
type RangeManager struct {
	ranges   map[string][]IPRange
	compiled map[string][]*net.IPNet
}

// NewRangeManager creates a new range manager
func NewRangeManager() *RangeManager {
	rm := &RangeManager{
		ranges:   make(map[string][]IPRange),
		compiled: make(map[string][]*net.IPNet),
	}
	rm.loadEmbeddedRanges()
	return rm
}

// loadEmbeddedRanges loads all embedded IP ranges
func (rm *RangeManager) loadEmbeddedRanges() {
	files := []string{
		"aws.json", "azure.json", "gcp.json", "cloudflare.json",
		"openai.json", "github.json", "deepseek.json", "anthropic.json",
		"tor.json", "vpn.json", "datacenter.json", "botnet.json",
		"malware.json", "threat.json", "scanner.json", "crawler.json",
	}

	for _, file := range files {
		if err := rm.loadRangeFile(file); err != nil {
			log.Printf("Warning: Failed to load range file %s: %v", file, err)
		}
	}
}

// loadRangeFile loads a specific range file
func (rm *RangeManager) loadRangeFile(filename string) error {
	data, err := rangeData.ReadFile("data/" + filename)
	if err != nil {
		return fmt.Errorf("failed to read %s: %w", filename, err)
	}

	var ranges []IPRange
	if err := json.Unmarshal(data, &ranges); err != nil {
		return fmt.Errorf("failed to unmarshal %s: %w", filename, err)
	}

	key := strings.TrimSuffix(filename, ".json")
	rm.ranges[key] = ranges
	
	// Pre-compile CIDR ranges for fast lookup
	var networks []*net.IPNet
	for _, r := range ranges {
		_, network, err := net.ParseCIDR(r.CIDR)
		if err != nil {
			log.Printf("Warning: Invalid CIDR %s in %s: %v", r.CIDR, filename, err)
			continue
		}
		networks = append(networks, network)
	}
	rm.compiled[key] = networks

	return nil
}

// AddCustomRange adds a custom IP range
func (rm *RangeManager) AddCustomRange(category string, ranges []IPRange) error {
	rm.ranges[category] = ranges
	
	var networks []*net.IPNet
	for _, r := range ranges {
		_, network, err := net.ParseCIDR(r.CIDR)
		if err != nil {
			return fmt.Errorf("invalid CIDR %s: %w", r.CIDR, err)
		}
		networks = append(networks, network)
	}
	rm.compiled[category] = networks
	
	return nil
}

// CheckIP checks if an IP belongs to any of the specified categories
func (rm *RangeManager) CheckIP(ip string, categories []string) (bool, []string) {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false, nil
	}

	var matches []string
	for _, category := range categories {
		networks, exists := rm.compiled[category]
		if !exists {
			continue
		}

		for _, network := range networks {
			if network.Contains(parsedIP) {
				matches = append(matches, category)
				break
			}
		}
	}

	return len(matches) > 0, matches
}

// GetAvailableCategories returns all available categories
func (rm *RangeManager) GetAvailableCategories() []string {
	var categories []string
	for category := range rm.ranges {
		categories = append(categories, category)
	}
	sort.Strings(categories)
	return categories
}

// GetRangeInfo returns information about a specific range category
func (rm *RangeManager) GetRangeInfo(category string) ([]IPRange, bool) {
	ranges, exists := rm.ranges[category]
	return ranges, exists
}

// Default categories for threat detection
var (
	DefaultThreatCategories = []string{
		"tor", "vpn", "botnet", "malware", "threat", "scanner",
	}
	
	DefaultAICategories = []string{
		"openai", "github", "deepseek", "anthropic", "aws", "azure", "gcp",
	}
	
	DefaultCloudCategories = []string{
		"aws", "azure", "gcp", "cloudflare", "datacenter",
	}
)
