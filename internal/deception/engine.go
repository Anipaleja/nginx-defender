package deception

import "strings"

type Engine struct {
	fakeEndpoints []string
}

func NewEngine() *Engine {
	return &Engine{fakeEndpoints: []string{
		"/.git/config",
		"/.env",
		"/wp-admin",
		"/phpmyadmin",
		"/admin/backup",
		"/trap/login",
		"/decoy/api",
	}}
}

func (e *Engine) Match(path string) (bool, string) {
	p := strings.ToLower(path)
	for _, endpoint := range e.fakeEndpoints {
		if strings.Contains(p, endpoint) {
			return true, endpoint
		}
	}
	return false, ""
}
