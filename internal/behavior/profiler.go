package behavior

import (
	"container/list"
	"math"
	"strings"
	"sync"
	"time"

	"github.com/Anipaleja/nginx-defender/pkg/logparser"
)

type Profile struct {
	IP                string
	LastSeen          time.Time
	TotalRequests     int
	UniqueEndpoints   map[string]int
	RecentTimestamps  []time.Time
	SuspiciousPaths   int
	LoginFailures     int
	HoneypotHits      int
	UserAgents        map[string]int
}

type ProfileSignals struct {
	BurstScore          float64
	ScrapingScore       float64
	CredentialStuffing  float64
	ProbingScore        float64
	EndpointEntropy     float64
	HoneypotScore       float64
}

type entry struct {
	key string
	val *Profile
}

type Profiler struct {
	mu       sync.Mutex
	capacity int
	ttl      time.Duration
	items    map[string]*list.Element
	order    *list.List
}

func NewProfiler(capacity int, ttl time.Duration) *Profiler {
	if capacity <= 0 {
		capacity = 50000
	}
	if ttl <= 0 {
		ttl = 30 * time.Minute
	}
	return &Profiler{capacity: capacity, ttl: ttl, items: map[string]*list.Element{}, order: list.New()}
}

func (p *Profiler) Observe(ip string, req *logparser.LogEntry) (*Profile, ProfileSignals) {
	if req == nil || ip == "" {
		return nil, ProfileSignals{}
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	if old, ok := p.items[ip]; ok {
		prof := old.Value.(*entry).val
		if time.Since(prof.LastSeen) > p.ttl {
			p.remove(old)
		}
	}

	el, ok := p.items[ip]
	if !ok {
		prof := &Profile{IP: ip, UniqueEndpoints: map[string]int{}, UserAgents: map[string]int{}}
		el = p.order.PushFront(&entry{key: ip, val: prof})
		p.items[ip] = el
	}

	p.order.MoveToFront(el)
	prof := el.Value.(*entry).val
	prof.LastSeen = req.Timestamp
	prof.TotalRequests++
	prof.UniqueEndpoints[req.Path]++
	prof.UserAgents[strings.ToLower(req.UserAgent)]++
	prof.RecentTimestamps = append(prof.RecentTimestamps, req.Timestamp)
	if len(prof.RecentTimestamps) > 200 {
		prof.RecentTimestamps = prof.RecentTimestamps[len(prof.RecentTimestamps)-200:]
	}

	pathLower := strings.ToLower(req.Path + " " + req.QueryString)
	if strings.Contains(pathLower, "login") && req.ResponseCode >= 400 {
		prof.LoginFailures++
	}
	if strings.Contains(pathLower, ".git") || strings.Contains(pathLower, "phpmyadmin") || strings.Contains(pathLower, "wp-admin") {
		prof.SuspiciousPaths++
	}
	if strings.Contains(pathLower, "/trap") || strings.Contains(pathLower, "/decoy") {
		prof.HoneypotHits++
	}

	for p.order.Len() > p.capacity {
		p.remove(p.order.Back())
	}

	sig := ProfileSignals{
		BurstScore:         burstScore(prof.RecentTimestamps),
		ScrapingScore:      scrapingScore(prof),
		CredentialStuffing: credentialStuffing(prof),
		ProbingScore:       probingScore(prof),
		EndpointEntropy:    endpointEntropy(prof.UniqueEndpoints, prof.TotalRequests),
		HoneypotScore:      math.Min(1.0, float64(prof.HoneypotHits)/3.0),
	}
	return prof, sig
}

func (p *Profiler) remove(el *list.Element) {
	if el == nil {
		return
	}
	ent := el.Value.(*entry)
	delete(p.items, ent.key)
	p.order.Remove(el)
}

func burstScore(ts []time.Time) float64 {
	if len(ts) < 5 {
		return 0
	}
	cut := ts[len(ts)-1].Add(-10 * time.Second)
	count := 0
	for i := len(ts) - 1; i >= 0; i-- {
		if ts[i].Before(cut) {
			break
		}
		count++
	}
	if count >= 80 {
		return 1.0
	}
	if count >= 40 {
		return 0.7
	}
	if count >= 20 {
		return 0.4
	}
	return 0
}

func scrapingScore(p *Profile) float64 {
	if p.TotalRequests < 40 {
		return 0
	}
	diversity := float64(len(p.UniqueEndpoints)) / float64(p.TotalRequests)
	if diversity > 0.85 {
		return 0.9
	}
	if diversity > 0.65 {
		return 0.6
	}
	return 0.2
}

func credentialStuffing(p *Profile) float64 {
	if p.LoginFailures >= 20 {
		return 0.95
	}
	if p.LoginFailures >= 10 {
		return 0.65
	}
	if p.LoginFailures >= 5 {
		return 0.3
	}
	return 0
}

func probingScore(p *Profile) float64 {
	if p.SuspiciousPaths >= 10 {
		return 0.9
	}
	if p.SuspiciousPaths >= 4 {
		return 0.6
	}
	if p.SuspiciousPaths > 0 {
		return 0.25
	}
	return 0
}

func endpointEntropy(unique map[string]int, total int) float64 {
	if total == 0 || len(unique) == 0 {
		return 0
	}
	var h float64
	for _, c := range unique {
		p := float64(c) / float64(total)
		if p > 0 {
			h -= p * math.Log2(p)
		}
	}
	maxH := math.Log2(float64(len(unique)))
	if maxH == 0 {
		return 0
	}
	return h / maxH
}
