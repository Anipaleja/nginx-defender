package plugins

import (
	"fmt"
	"plugin"
	"sync"

	"github.com/Anipaleja/nginx-defender/pkg/logparser"
)

type DetectionContext struct {
	ThreatTypes []string
	Score       float64
	Details     map[string]string
}

type DetectionPlugin interface {
	Name() string
	Detect(entry *logparser.LogEntry, ctx *DetectionContext)
}

type Manager struct {
	mu      sync.RWMutex
	plugins []DetectionPlugin
}

func NewManager() *Manager {
	return &Manager{plugins: []DetectionPlugin{}}
}

func (m *Manager) Register(p DetectionPlugin) {
	if p == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.plugins = append(m.plugins, p)
}

func (m *Manager) Run(entry *logparser.LogEntry, ctx *DetectionContext) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, p := range m.plugins {
		p.Detect(entry, ctx)
	}
}

func (m *Manager) LoadSharedObject(path string) error {
	mod, err := plugin.Open(path)
	if err != nil {
		return fmt.Errorf("open plugin: %w", err)
	}
	sym, err := mod.Lookup("Plugin")
	if err != nil {
		return fmt.Errorf("lookup Plugin symbol: %w", err)
	}
	plg, ok := sym.(DetectionPlugin)
	if !ok {
		return fmt.Errorf("plugin does not implement DetectionPlugin")
	}
	m.Register(plg)
	return nil
}

func (m *Manager) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.plugins)
}
