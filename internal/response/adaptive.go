package response

import "github.com/Anipaleja/nginx-defender/internal/detector"

type Decision struct {
	Action    string
	Escalate  bool
}

func Plan(result *detector.DetectionResult) Decision {
	if result == nil {
		return Decision{Action: "MONITOR"}
	}

	action := result.RecommendedAction
	conf := result.Confidence

	if conf >= 0.92 {
		return Decision{Action: "BLOCK_IMMEDIATE", Escalate: true}
	}

	if conf < 0.45 && result.ThreatLevel <= detector.ThreatLevelMedium {
		return Decision{Action: "MONITOR", Escalate: false}
	}

	if conf >= 0.7 && action == "RATE_LIMIT" {
		return Decision{Action: "BLOCK", Escalate: true}
	}

	if conf >= 0.6 && action == "MONITOR" {
		return Decision{Action: "RATE_LIMIT", Escalate: false}
	}

	return Decision{Action: action, Escalate: false}
}
