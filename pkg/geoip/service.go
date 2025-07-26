package geoip

import (
	"fmt"
	"net"

	"github.com/Anipaleja/nginx-defender/internal/config"
	"github.com/oschwald/geoip2-golang"
)

// Service provides GeoIP lookup functionality
type Service struct {
	db     *geoip2.Reader
	config config.GeographicConfig
}

// LocationInfo contains geographic information about an IP
type LocationInfo struct {
	Country     string  `json:"country"`
	CountryCode string  `json:"country_code"`
	City        string  `json:"city"`
	Latitude    float64 `json:"latitude"`
	Longitude   float64 `json:"longitude"`
	ISP         string  `json:"isp"`
	Organization string `json:"organization"`
}

// NewService creates a new GeoIP service
func NewService(cfg config.GeographicConfig) (*Service, error) {
	if !cfg.Enabled {
		return &Service{config: cfg}, nil
	}
	
	// Try to open GeoLite2 database
	dbPaths := []string{
		"/usr/share/GeoIP/GeoLite2-City.mmdb",
		"/var/lib/GeoIP/GeoLite2-City.mmdb",
		"./GeoLite2-City.mmdb",
		"/opt/geoip/GeoLite2-City.mmdb",
	}
	
	var db *geoip2.Reader
	var err error
	
	for _, path := range dbPaths {
		db, err = geoip2.Open(path)
		if err == nil {
			break
		}
	}
	
	if err != nil {
		return nil, fmt.Errorf("failed to open GeoIP database: %v", err)
	}
	
	return &Service{
		db:     db,
		config: cfg,
	}, nil
}

// GetCountry returns the country for an IP address
func (s *Service) GetCountry(ipStr string) (string, error) {
	if s.db == nil {
		return "Unknown", fmt.Errorf("GeoIP database not available")
	}
	
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return "Unknown", fmt.Errorf("invalid IP address: %s", ipStr)
	}
	
	record, err := s.db.City(ip)
	if err != nil {
		return "Unknown", err
	}
	
	return record.Country.Names["en"], nil
}

// GetLocationInfo returns detailed location information for an IP
func (s *Service) GetLocationInfo(ipStr string) (*LocationInfo, error) {
	if s.db == nil {
		return nil, fmt.Errorf("GeoIP database not available")
	}
	
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP address: %s", ipStr)
	}
	
	record, err := s.db.City(ip)
	if err != nil {
		return nil, err
	}
	
	info := &LocationInfo{
		Country:     record.Country.Names["en"],
		CountryCode: record.Country.IsoCode,
		City:        record.City.Names["en"],
		Latitude:    float64(record.Location.Latitude),
		Longitude:   float64(record.Location.Longitude),
	}
	
	// Try to get ISP information if available
	if len(record.Traits.ISP) > 0 {
		info.ISP = record.Traits.ISP
	}
	if len(record.Traits.Organization) > 0 {
		info.Organization = record.Traits.Organization
	}
	
	return info, nil
}

// IsBlocked checks if an IP is from a blocked country
func (s *Service) IsBlocked(ipStr string) (bool, string, error) {
	country, err := s.GetCountry(ipStr)
	if err != nil {
		return false, "", err
	}
	
	// Check blocked countries
	for _, blocked := range s.config.BlockedCountries {
		if country == blocked {
			return true, country, nil
		}
	}
	
	// Check allowed countries (if any specified)
	if len(s.config.AllowedCountries) > 0 {
		for _, allowed := range s.config.AllowedCountries {
			if country == allowed {
				return false, country, nil
			}
		}
		// If allowed countries are specified and this country is not in the list, block it
		return true, country, nil
	}
	
	return false, country, nil
}

// Close closes the GeoIP database
func (s *Service) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}
