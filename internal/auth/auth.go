package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/Anipaleja/nginx-defender/internal/config"
	"github.com/golang-jwt/jwt/v5"
	"github.com/pquerna/otp/totp"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
)

// AuthManager handles all authentication operations
type AuthManager struct {
	config          *config.AuthConfig
	logger          *logrus.Logger
	userStore       *UserStore
	sessionStore    *SessionStore
	apiKeyStore     *APIKeyStore
	auditLogger     *AuditLogger
	resetTokenStore *PasswordResetStore
	jwtSecret       []byte
	mutex           sync.RWMutex
	shutdownCtx     context.Context
	shutdownCancel  context.CancelFunc
	shutdownOnce    sync.Once
}

// UserStore manages user data
type UserStore struct {
	users map[string]*User
	mutex sync.RWMutex
}

// User represents a system user
type User struct {
	Username     string
	Email        string
	PasswordHash string
	Roles        []string
	TwoFAEnabled bool
	TwoFASecret  string
	BackupCodes  []string
	APIKeys      []*APIKey
	LastLogin    *time.Time
	CreatedAt    time.Time
	UpdatedAt    time.Time
	Active       bool
	FailedLogins int
	LockedUntil  *time.Time
}

// Session represents an authenticated session
type Session struct {
	ID            string
	UserID        string
	Username      string
	Roles         []string
	CreatedAt     time.Time
	ExpiresAt     time.Time
	LastActivity  time.Time
	IPAddress     string
	UserAgent     string
	TwoFAVerified bool
}

// SessionStore manages active sessions
type SessionStore struct {
	sessions map[string]*Session
	mutex    sync.RWMutex
}

// APIKey represents an API key for authentication
type APIKey struct {
	ID          string
	Key         string
	UserID      string
	Name        string
	Permissions []string
	CreatedAt   time.Time
	ExpiresAt   *time.Time
	LastUsed    *time.Time
	Active      bool
}

// APIKeyStore manages API keys
type APIKeyStore struct {
	keys  map[string]*APIKey
	mutex sync.RWMutex
}

// JWTClaims represents JWT token claims
type JWTClaims struct {
	Username string   `json:"username"`
	Roles    []string `json:"roles"`
	jwt.RegisteredClaims
}

// PasswordResetToken represents a password reset token
type PasswordResetToken struct {
	Token     string
	UserID    string
	ExpiresAt time.Time
	Used      bool
}

// PasswordResetStore manages password reset tokens
type PasswordResetStore struct {
	tokens map[string]*PasswordResetToken
	mutex  sync.RWMutex
}

// AuditLogger placeholder type (implementation would be in a separate file)
type AuditLogger struct {
	enabled bool
}

// LogEvent logs an audit event (placeholder implementation)
func (al *AuditLogger) LogEvent(eventType, username, identifier string, metadata map[string]interface{}) {
	// Placeholder implementation
	if al.enabled {
		// In a real implementation, this would log to a file or database
	}
}

// NewAuthManager creates a new authentication manager
func NewAuthManager(cfg *config.AuthConfig, logger *logrus.Logger) (*AuthManager, error) {
	ctx, cancel := context.WithCancel(context.Background())
	am := &AuthManager{
		config:         cfg,
		logger:         logger,
		userStore:      &UserStore{users: make(map[string]*User)},
		sessionStore:   &SessionStore{sessions: make(map[string]*Session)},
		apiKeyStore:    &APIKeyStore{keys: make(map[string]*APIKey)},
		shutdownCtx:    ctx,
		shutdownCancel: cancel,
	}

	// Initialize JWT secret
	if cfg.JWT.Enabled {
		am.jwtSecret = []byte(cfg.JWT.Secret)
		if am.jwtSecret == nil || len(am.jwtSecret) == 0 {
			// Generate a random secret if not provided
			secret := make([]byte, 32)
			n, err := rand.Read(secret)
			if err != nil || n != len(secret) {
				return nil, fmt.Errorf("failed to generate JWT secret: %w", err)
			}
			am.jwtSecret = secret
		}
	}

	// Initialize audit logger if enabled
	if cfg.AuditLogging.Enabled {
		am.auditLogger = &AuditLogger{enabled: true}
	}

	// Load initial users from config
	am.loadUsersFromConfig()

	// Initialize password reset token store
	am.resetTokenStore = &PasswordResetStore{
		tokens: make(map[string]*PasswordResetToken),
		mutex:  sync.RWMutex{},
	}

	// Start session cleanup routine
	go am.sessionCleanupRoutine()

	return am, nil
}

// loadUsersFromConfig loads users from configuration
func (am *AuthManager) loadUsersFromConfig() {
	for _, userConfig := range am.config.Users {
		passwordHash := userConfig.Password

		// Hash the password if it's not already hashed
		if am.config.PasswordHashAlgo == "bcrypt" && !isBcryptHash(passwordHash) {
			hash, err := bcrypt.GenerateFromPassword([]byte(userConfig.Password), bcrypt.DefaultCost)
			if err != nil {
				am.logger.WithError(err).Errorf("Failed to hash password for user %s", userConfig.Username)
				continue
			}
			passwordHash = string(hash)
		}

		user := &User{
			Username:     userConfig.Username,
			Email:        userConfig.Email,
			PasswordHash: passwordHash,
			Roles:        userConfig.Roles,
			TwoFAEnabled: userConfig.TwoFAEnabled,
			TwoFASecret:  userConfig.TwoFASecret,
			Active:       userConfig.Active,
			CreatedAt:    userConfig.CreatedAt,
			UpdatedAt:    userConfig.UpdatedAt,
			APIKeys:      []*APIKey{},
		}

		// Set default values
		if len(user.Roles) == 0 {
			user.Roles = []string{"user"}
		}
		if user.CreatedAt.IsZero() {
			user.CreatedAt = time.Now()
		}
		if user.UpdatedAt.IsZero() {
			user.UpdatedAt = time.Now()
		}

		am.userStore.users[user.Username] = user
	}

	// Add default user if no users are configured
	if len(am.userStore.users) == 0 && am.config.DefaultUsername != "" {
		passwordHash := am.config.DefaultPassword
		if am.config.PasswordHashAlgo == "bcrypt" {
			hash, err := bcrypt.GenerateFromPassword([]byte(am.config.DefaultPassword), bcrypt.DefaultCost)
			if err != nil {
				am.logger.WithError(err).Errorf("Failed to hash default password for user %s", am.config.DefaultUsername)
				// Skip creating the default user rather than storing plaintext password
				return
			}
			passwordHash = string(hash)
		}

		am.userStore.users[am.config.DefaultUsername] = &User{
			Username:     am.config.DefaultUsername,
			PasswordHash: passwordHash,
			Roles:        []string{"admin"},
			Active:       true,
			CreatedAt:    time.Now(),
			UpdatedAt:    time.Now(),
		}
	}
}

// ValidateCredentials validates username and password
func (am *AuthManager) ValidateCredentials(username, password string) (*User, error) {
	am.userStore.mutex.RLock()
	user, exists := am.userStore.users[username]
	am.userStore.mutex.RUnlock()

	if !exists {
		am.logAuthEvent("login_failed", username, "user_not_found", nil)
		return nil, errors.New("invalid credentials")
	}

	// Check if account is locked
	if user.LockedUntil != nil && user.LockedUntil.After(time.Now()) {
		am.logAuthEvent("login_failed", username, "account_locked", nil)
		return nil, errors.New("invalid credentials")
	}

	// Check if account is active
	if !user.Active {
		am.logAuthEvent("login_failed", username, "account_inactive", nil)
		return nil, errors.New("invalid credentials")
	}

	// Validate password
	var valid bool
	if am.config.PasswordHashAlgo == "bcrypt" {
		err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password))
		valid = err == nil
	} else {
		valid = user.PasswordHash == password
	}

	if !valid {
		am.handleFailedLogin(user)
		am.logAuthEvent("login_failed", username, "invalid_password", nil)
		return nil, errors.New("invalid credentials")
	}

	// Reset failed login count on successful login
	user.FailedLogins = 0
	t := time.Now()
	user.LastLogin = &t

	am.logAuthEvent("login_success", username, "", nil)
	return user, nil
}

// handleFailedLogin handles failed login attempts
func (am *AuthManager) handleFailedLogin(user *User) {
	am.userStore.mutex.Lock()
	defer am.userStore.mutex.Unlock()

	user.FailedLogins++

	// Lock account after 5 failed attempts
	if user.FailedLogins >= 5 {
		lockUntil := time.Now().Add(30 * time.Minute)
		user.LockedUntil = &lockUntil
		am.logger.Warnf("Account %s locked due to multiple failed login attempts", user.Username)
	}
}

// CreateSession creates a new session for a user
func (am *AuthManager) CreateSession(user *User, ipAddress, userAgent string) (*Session, error) {
	sessionID, err := generateSessionID()
	if err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	session := &Session{
		ID:            sessionID,
		UserID:        user.Username,
		Username:      user.Username,
		Roles:         user.Roles,
		CreatedAt:     time.Now(),
		ExpiresAt:     time.Now().Add(time.Duration(am.config.SessionTimeout) * time.Second),
		LastActivity:  time.Now(),
		IPAddress:     ipAddress,
		UserAgent:     userAgent,
		TwoFAVerified: !user.TwoFAEnabled, // If 2FA is not enabled, consider it verified
	}

	am.sessionStore.mutex.Lock()
	am.sessionStore.sessions[sessionID] = session
	am.sessionStore.mutex.Unlock()

	am.logAuthEvent("session_created", user.Username, sessionID, map[string]interface{}{
		"ip":         ipAddress,
		"user_agent": userAgent,
	})

	return session, nil
}

// ValidateSession validates a session ID
func (am *AuthManager) ValidateSession(sessionID string) (*Session, error) {
	am.sessionStore.mutex.RLock()
	session, exists := am.sessionStore.sessions[sessionID]
	am.sessionStore.mutex.RUnlock()

	if !exists {
		return nil, errors.New("session not found")
	}

	if session.ExpiresAt.Before(time.Now()) {
		am.DestroySession(sessionID)
		return nil, errors.New("session expired")
	}

	// Update last activity
	am.sessionStore.mutex.Lock()
	session.LastActivity = time.Now()
	am.sessionStore.mutex.Unlock()

	return session, nil
}

// DestroySession destroys a session
func (am *AuthManager) DestroySession(sessionID string) {
	am.sessionStore.mutex.Lock()
	if session, exists := am.sessionStore.sessions[sessionID]; exists {
		delete(am.sessionStore.sessions, sessionID)
		am.logAuthEvent("session_destroyed", session.Username, sessionID, nil)
	}
	am.sessionStore.mutex.Unlock()
}

// GenerateJWT generates a JWT token for a user
func (am *AuthManager) GenerateJWT(user *User) (string, error) {
	if !am.config.JWT.Enabled {
		return "", errors.New("JWT authentication is not enabled")
	}

	expiresAt := time.Now().Add(am.config.JWT.Expiration)
	claims := &JWTClaims{
		Username: user.Username,
		Roles:    user.Roles,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    am.config.JWT.Issuer,
			Subject:   user.Username,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(am.jwtSecret)
	if err != nil {
		return "", err
	}

	am.logAuthEvent("jwt_generated", user.Username, "", map[string]interface{}{
		"expires_at": expiresAt.Unix(),
	})

	return tokenString, nil
}

// ValidateJWT validates a JWT token
func (am *AuthManager) ValidateJWT(tokenString string) (*JWTClaims, error) {
	if !am.config.JWT.Enabled {
		return nil, errors.New("JWT authentication is not enabled")
	}

	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return am.jwtSecret, nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*JWTClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, errors.New("invalid token")
}

// GenerateTOTPSecret generates a new TOTP secret for a user
func (am *AuthManager) GenerateTOTPSecret(username string) (string, string, error) {
	am.userStore.mutex.RLock()
	user, exists := am.userStore.users[username]
	am.userStore.mutex.RUnlock()

	if !exists {
		return "", "", errors.New("user not found")
	}

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      am.config.TwoFA.Issuer,
		AccountName: username,
	})

	if err != nil {
		return "", "", err
	}

	// Update user's 2FA secret
	am.userStore.mutex.Lock()
	user.TwoFASecret = key.Secret()
	user.UpdatedAt = time.Now()
	am.userStore.mutex.Unlock()

	am.logAuthEvent("2fa_secret_generated", username, "", nil)

	return key.Secret(), key.URL(), nil
}

// ValidateTOTP validates a TOTP code
func (am *AuthManager) ValidateTOTP(username, code string) error {
	am.userStore.mutex.RLock()
	user, exists := am.userStore.users[username]
	am.userStore.mutex.RUnlock()

	if !exists {
		return errors.New("user not found")
	}

	if !user.TwoFAEnabled || user.TwoFASecret == "" {
		return errors.New("2FA not enabled for user")
	}

	valid := totp.Validate(code, user.TwoFASecret)
	if !valid {
		am.logAuthEvent("2fa_validation_failed", username, "", nil)
		return errors.New("invalid 2FA code")
	}

	am.logAuthEvent("2fa_validation_success", username, "", nil)
	return nil
}

// GenerateAPIKey generates a new API key for a user
func (am *AuthManager) GenerateAPIKey(username, keyName string, permissions []string) (*APIKey, error) {
	am.userStore.mutex.RLock()
	user, exists := am.userStore.users[username]
	am.userStore.mutex.RUnlock()

	if !exists {
		return nil, errors.New("user not found")
	}

	// Check max keys limit
	if am.config.APIKeys.MaxKeys > 0 && len(user.APIKeys) >= am.config.APIKeys.MaxKeys {
		return nil, fmt.Errorf("maximum number of API keys (%d) reached", am.config.APIKeys.MaxKeys)
	}

	// Generate key
	keyBytes := make([]byte, am.config.APIKeys.KeyLength)
	if _, err := rand.Read(keyBytes); err != nil {
		return nil, err
	}

	keyString := am.config.APIKeys.Prefix + base64.URLEncoding.EncodeToString(keyBytes)
	keyID, err := generateKeyID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate key ID: %w", err)
	}

	var expiresAt *time.Time
	if am.config.APIKeys.DefaultExpiry > 0 {
		expiry := time.Now().Add(am.config.APIKeys.DefaultExpiry)
		expiresAt = &expiry
	}

	apiKey := &APIKey{
		ID:          keyID,
		Key:         keyString,
		UserID:      username,
		Name:        keyName,
		Permissions: permissions,
		CreatedAt:   time.Now(),
		ExpiresAt:   expiresAt,
		Active:      true,
	}

	// Store the key
	am.apiKeyStore.mutex.Lock()
	am.apiKeyStore.keys[keyString] = apiKey
	am.apiKeyStore.mutex.Unlock()

	// Add to user's keys
	am.userStore.mutex.Lock()
	user.APIKeys = append(user.APIKeys, apiKey)
	am.userStore.mutex.Unlock()

	am.logAuthEvent("api_key_generated", username, keyID, map[string]interface{}{
		"name":       keyName,
		"expires_at": expiresAt,
	})

	return apiKey, nil
}

// ValidateAPIKey validates an API key
func (am *AuthManager) ValidateAPIKey(keyString string) (*APIKey, error) {
	if !am.config.APIKeys.Enabled {
		return nil, errors.New("API key authentication is not enabled")
	}

	am.apiKeyStore.mutex.RLock()
	apiKey, exists := am.apiKeyStore.keys[keyString]
	am.apiKeyStore.mutex.RUnlock()

	if !exists {
		return nil, errors.New("invalid API key")
	}

	if !apiKey.Active {
		return nil, errors.New("API key is inactive")
	}

	if apiKey.ExpiresAt != nil && apiKey.ExpiresAt.Before(time.Now()) {
		return nil, errors.New("API key has expired")
	}

	// Update last used
	am.apiKeyStore.mutex.Lock()
	now := time.Now()
	apiKey.LastUsed = &now
	am.apiKeyStore.mutex.Unlock()

	return apiKey, nil
}

// GeneratePasswordResetToken generates a password reset token
func (am *AuthManager) GeneratePasswordResetToken(email string) (*PasswordResetToken, error) {
	// Find user by email
	var user *User
	am.userStore.mutex.RLock()
	for _, u := range am.userStore.users {
		if u.Email == email {
			user = u
			break
		}
	}
	am.userStore.mutex.RUnlock()

	if user == nil {
		// Don't reveal whether email exists
		return nil, nil
	}

	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return nil, err
	}

	token := &PasswordResetToken{
		Token:     hex.EncodeToString(tokenBytes),
		UserID:    user.Username,
		ExpiresAt: time.Now().Add(am.config.PasswordReset.TokenExpiry),
		Used:      false,
	}

	// Store the token
	am.resetTokenStore.mutex.Lock()
	am.resetTokenStore.tokens[token.Token] = token
	am.resetTokenStore.mutex.Unlock()

	am.logAuthEvent("password_reset_requested", user.Username, "", map[string]interface{}{
		"email": email,
	})

	return token, nil
}

// ResetPassword resets a user's password using a token
func (am *AuthManager) ResetPassword(token, newPassword string) error {
	// Acquire write lock on reset token store and hold until token is marked used
	am.resetTokenStore.mutex.Lock()
	defer am.resetTokenStore.mutex.Unlock()

	// 1. Validate the token exists in the token store
	resetToken, exists := am.resetTokenStore.tokens[token]
	if !exists {
		return errors.New("invalid or expired reset token")
	}

	// 2. Check token expiry and that it has not been used (while holding write lock)
	if resetToken.Used {
		return errors.New("reset token has already been used")
	}

	if time.Now().After(resetToken.ExpiresAt) {
		return errors.New("reset token has expired")
	}

	// 3. Find the user (need separate lock for user store)
	am.userStore.mutex.Lock()
	user, userExists := am.userStore.users[resetToken.UserID]
	if !userExists {
		am.userStore.mutex.Unlock()
		return errors.New("user not found")
	}

	// 4. Hash the new password
	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		am.userStore.mutex.Unlock()
		return fmt.Errorf("failed to hash password: %w", err)
	}

	// 5. Update the user's password field
	user.PasswordHash = string(hash)
	am.userStore.mutex.Unlock()

	// 6. Mark the reset token as used (still holding resetTokenStore write lock)
	resetToken.Used = true

	am.logAuthEvent("password_reset_completed", user.Username, token, nil)

	return nil
}

// HasPermission checks if a user has a specific permission
func (am *AuthManager) HasPermission(username, permission string) bool {
	am.userStore.mutex.RLock()
	user, exists := am.userStore.users[username]
	am.userStore.mutex.RUnlock()

	if !exists || !user.Active {
		return false
	}

	// Check role-based permissions
	for _, role := range user.Roles {
		if hasRolePermission(role, permission) {
			return true
		}
	}

	return false
}

// sessionCleanupRoutine periodically cleans up expired sessions
func (am *AuthManager) sessionCleanupRoutine() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			am.sessionStore.mutex.Lock()
			now := time.Now()
			for sessionID, session := range am.sessionStore.sessions {
				if session.ExpiresAt.Before(now) {
					delete(am.sessionStore.sessions, sessionID)
					am.logger.Debugf("Cleaned up expired session: %s", sessionID)
				}
			}
			am.sessionStore.mutex.Unlock()
		case <-am.shutdownCtx.Done():
			am.logger.Debug("Session cleanup routine shutting down")
			return
		}
	}
}

// Shutdown gracefully shuts down the AuthManager and stops background routines
func (am *AuthManager) Shutdown() {
	am.shutdownOnce.Do(func() {
		am.logger.Debug("Shutting down AuthManager")
		am.shutdownCancel()
	})
}

// logAuthEvent logs an authentication event
func (am *AuthManager) logAuthEvent(eventType, username, identifier string, metadata map[string]interface{}) {
	if am.auditLogger != nil {
		am.auditLogger.LogEvent(eventType, username, identifier, metadata)
	}
}

// Helper functions

func generateSessionID() (string, error) {
	bytes := make([]byte, 32)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", fmt.Errorf("failed to generate session ID: %w", err)
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

func generateKeyID() (string, error) {
	bytes := make([]byte, 16)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", fmt.Errorf("failed to generate key ID: %w", err)
	}
	return hex.EncodeToString(bytes), nil
}

func isBcryptHash(s string) bool {
	// Bcrypt hashes start with $2a$, $2b$, or $2y$
	return len(s) >= 4 && s[0] == '$' && s[1] == '2' && (s[2] == 'a' || s[2] == 'b' || s[2] == 'y') && s[3] == '$'
}

func hasRolePermission(role, permission string) bool {
	// Define role-based permissions
	rolePermissions := map[string][]string{
		"admin": {"*"}, // Admin has all permissions
		"operator": {
			"view_dashboard",
			"view_logs",
			"view_threats",
			"manage_firewall",
		},
		"viewer": {
			"view_dashboard",
			"view_logs",
		},
	}

	permissions, exists := rolePermissions[role]
	if !exists {
		return false
	}

	for _, p := range permissions {
		if p == "*" || p == permission {
			return true
		}
	}

	return false
}
