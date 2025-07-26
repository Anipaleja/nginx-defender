package firewall

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/Anipaleja/nginx-defender/internal/config"
	"github.com/sirupsen/logrus"
)

// IptablesBackend implements firewall operations using iptables
type IptablesBackend struct {
	config config.FirewallConfig
	logger *logrus.Logger
	chain  string
}

// NewIptablesBackend creates a new iptables backend
func NewIptablesBackend(cfg config.FirewallConfig, logger *logrus.Logger) (*IptablesBackend, error) {
	backend := &IptablesBackend{
		config: cfg,
		logger: logger,
		chain:  cfg.Chain,
	}
	
	// Initialize iptables chain
	if err := backend.initializeChain(); err != nil {
		return nil, fmt.Errorf("failed to initialize iptables chain: %v", err)
	}
	
	return backend, nil
}

// Name returns the backend name
func (b *IptablesBackend) Name() string {
	return "iptables"
}

// AddRule adds a firewall rule using iptables
func (b *IptablesBackend) AddRule(rule *Rule) error {
	var commands [][]string
	
	switch rule.Action {
	case ActionBlock, ActionDrop:
		commands = append(commands, []string{
			"iptables", "-I", b.chain, "-s", rule.IP, "-j", "DROP",
			"-m", "comment", "--comment", fmt.Sprintf("nginx-defender:%s:%s", rule.ID, rule.Reason),
		})
		
		if b.config.IPv6Support {
			commands = append(commands, []string{
				"ip6tables", "-I", b.chain, "-s", rule.IP, "-j", "DROP",
				"-m", "comment", "--comment", fmt.Sprintf("nginx-defender:%s:%s", rule.ID, rule.Reason),
			})
		}
		
	case ActionReject:
		commands = append(commands, []string{
			"iptables", "-I", b.chain, "-s", rule.IP, "-j", "REJECT",
			"--reject-with", "icmp-host-prohibited",
			"-m", "comment", "--comment", fmt.Sprintf("nginx-defender:%s:%s", rule.ID, rule.Reason),
		})
		
		if b.config.IPv6Support {
			commands = append(commands, []string{
				"ip6tables", "-I", b.chain, "-s", rule.IP, "-j", "REJECT",
				"--reject-with", "icmp6-adm-prohibited",
				"-m", "comment", "--comment", fmt.Sprintf("nginx-defender:%s:%s", rule.ID, rule.Reason),
			})
		}
		
	case ActionRateLimit:
		// Implement rate limiting using iptables recent module
		limit := "10/minute" // Default limit
		if limitStr, exists := rule.Metadata["limit"]; exists {
			limit = limitStr
		}
		
		commands = append(commands, []string{
			"iptables", "-I", b.chain, "-s", rule.IP,
			"-m", "recent", "--set", "--name", fmt.Sprintf("nginx_defender_%s", strings.ReplaceAll(rule.IP, ".", "_")),
		})
		
		commands = append(commands, []string{
			"iptables", "-I", b.chain, "-s", rule.IP,
			"-m", "recent", "--update", "--seconds", "60", "--hitcount", "10",
			"--name", fmt.Sprintf("nginx_defender_%s", strings.ReplaceAll(rule.IP, ".", "_")),
			"-j", "DROP",
			"-m", "comment", "--comment", fmt.Sprintf("nginx-defender:%s:rate-limit", rule.ID),
		})
		
	case ActionTarpit:
		// Implement tarpit using TARPIT target (if available) or REJECT with delay
		commands = append(commands, []string{
			"iptables", "-I", b.chain, "-s", rule.IP, "-p", "tcp",
			"-j", "TARPIT",
			"-m", "comment", "--comment", fmt.Sprintf("nginx-defender:%s:tarpit", rule.ID),
		})
		
		// Fallback to REJECT if TARPIT is not available
		fallbackCmd := []string{
			"iptables", "-I", b.chain, "-s", rule.IP,
			"-j", "REJECT", "--reject-with", "tcp-reset",
			"-m", "comment", "--comment", fmt.Sprintf("nginx-defender:%s:tarpit-fallback", rule.ID),
		}
		commands = append(commands, fallbackCmd)
	}
	
	// Execute commands
	for _, cmd := range commands {
		if err := b.executeCommand(cmd); err != nil {
			// If TARPIT failed, try fallback
			if rule.Action == ActionTarpit && strings.Contains(err.Error(), "TARPIT") {
				continue // Try the fallback command
			}
			return fmt.Errorf("failed to execute iptables command %v: %v", cmd, err)
		}
		break // If successful, don't try other commands
	}
	
	b.logger.Debugf("Added iptables rule for IP %s with action %s", rule.IP, rule.Action)
	return nil
}

// RemoveRule removes a firewall rule
func (b *IptablesBackend) RemoveRule(ruleID string) error {
	// List all rules and find the one with our comment
	rules, err := b.listRulesWithComments()
	if err != nil {
		return fmt.Errorf("failed to list rules: %v", err)
	}
	
	for _, ruleInfo := range rules {
		if strings.Contains(ruleInfo.comment, ruleID) {
			// Remove the rule
			cmd := []string{"iptables", "-D", b.chain}
			cmd = append(cmd, ruleInfo.spec...)
			
			if err := b.executeCommand(cmd); err != nil {
				return fmt.Errorf("failed to remove iptables rule: %v", err)
			}
			
			// Also try IPv6 if enabled
			if b.config.IPv6Support {
				cmd6 := []string{"ip6tables", "-D", b.chain}
				cmd6 = append(cmd6, ruleInfo.spec...)
				b.executeCommand(cmd6) // Ignore errors for IPv6
			}
			
			b.logger.Debugf("Removed iptables rule with ID %s", ruleID)
			break
		}
	}
	
	return nil
}

// ListRules lists all active rules
func (b *IptablesBackend) ListRules() ([]*Rule, error) {
	rules := []*Rule{}
	
	ruleInfos, err := b.listRulesWithComments()
	if err != nil {
		return nil, err
	}
	
	for _, ruleInfo := range ruleInfos {
		if !strings.Contains(ruleInfo.comment, "nginx-defender:") {
			continue
		}
		
		// Parse comment to extract rule information
		parts := strings.Split(ruleInfo.comment, ":")
		if len(parts) < 3 {
			continue
		}
		
		rule := &Rule{
			ID:        parts[1],
			Reason:    strings.Join(parts[2:], ":"),
			CreatedAt: time.Now(), // We don't store creation time in iptables
			ExpiresAt: time.Now().Add(24 * time.Hour), // Default expiration
		}
		
		// Extract IP from rule spec
		for i, arg := range ruleInfo.spec {
			if arg == "-s" && i+1 < len(ruleInfo.spec) {
				rule.IP = ruleInfo.spec[i+1]
				break
			}
		}
		
		// Determine action from rule spec
		for i, arg := range ruleInfo.spec {
			if arg == "-j" && i+1 < len(ruleInfo.spec) {
				switch ruleInfo.spec[i+1] {
				case "DROP":
					rule.Action = ActionDrop
				case "REJECT":
					rule.Action = ActionReject
				case "TARPIT":
					rule.Action = ActionTarpit
				default:
					rule.Action = ActionBlock
				}
				break
			}
		}
		
		rules = append(rules, rule)
	}
	
	return rules, nil
}

// IsBlocked checks if an IP is blocked
func (b *IptablesBackend) IsBlocked(ip string) (bool, error) {
	rules, err := b.ListRules()
	if err != nil {
		return false, err
	}
	
	for _, rule := range rules {
		if rule.IP == ip {
			return true, nil
		}
	}
	
	return false, nil
}

// Flush removes all rules managed by nginx-defender
func (b *IptablesBackend) Flush() error {
	rules, err := b.listRulesWithComments()
	if err != nil {
		return err
	}
	
	for _, ruleInfo := range rules {
		if strings.Contains(ruleInfo.comment, "nginx-defender:") {
			cmd := []string{"iptables", "-D", b.chain}
			cmd = append(cmd, ruleInfo.spec...)
			b.executeCommand(cmd) // Ignore individual errors
		}
	}
	
	b.logger.Info("Flushed all nginx-defender iptables rules")
	return nil
}

// initializeChain initializes the iptables chain
func (b *IptablesBackend) initializeChain() error {
	// Create chain if it doesn't exist
	if b.chain != "INPUT" && b.chain != "FORWARD" && b.chain != "OUTPUT" {
		cmd := []string{"iptables", "-N", b.chain}
		if err := b.executeCommand(cmd); err != nil {
			// Chain might already exist, ignore error
		}
		
		if b.config.IPv6Support {
			cmd6 := []string{"ip6tables", "-N", b.chain}
			b.executeCommand(cmd6) // Ignore errors
		}
	}
	
	return nil
}

// executeCommand executes an iptables command
func (b *IptablesBackend) executeCommand(args []string) error {
	cmd := exec.Command(args[0], args[1:]...)
	output, err := cmd.CombinedOutput()
	
	if err != nil {
		return fmt.Errorf("command failed: %s, output: %s", err, string(output))
	}
	
	return nil
}

// ruleInfo holds information about an iptables rule
type ruleInfo struct {
	spec    []string
	comment string
}

// listRulesWithComments lists all rules with their comments
func (b *IptablesBackend) listRulesWithComments() ([]ruleInfo, error) {
	cmd := exec.Command("iptables", "-L", b.chain, "-n", "--line-numbers")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to list iptables rules: %v", err)
	}
	
	var rules []ruleInfo
	lines := strings.Split(string(output), "\n")
	
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Chain") || strings.HasPrefix(line, "num") {
			continue
		}
		
		// Parse rule line
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		
		// Extract comment if present
		comment := ""
		for i, field := range fields {
			if field == "/*" && i+1 < len(fields) {
				// Find the end of comment
				for j := i + 1; j < len(fields); j++ {
					if strings.HasSuffix(fields[j], "*/") {
						commentParts := fields[i+1 : j+1]
						comment = strings.Join(commentParts, " ")
						comment = strings.TrimSuffix(strings.TrimPrefix(comment, "/* "), " */")
						break
					}
				}
				break
			}
		}
		
		// Create rule spec (simplified)
		spec := []string{}
		if len(fields) > 4 {
			// Add source if not "anywhere"
			if fields[4] != "0.0.0.0/0" && fields[4] != "anywhere" {
				spec = append(spec, "-s", fields[4])
			}
			// Add target
			if fields[2] != "" {
				spec = append(spec, "-j", fields[2])
			}
		}
		
		rules = append(rules, ruleInfo{
			spec:    spec,
			comment: comment,
		})
	}
	
	return rules, nil
}
