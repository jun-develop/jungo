package v1

import (
	"time"

	"github.com/google/uuid"

	"jungo/internal/features/auth/domain"
)

// LoginRequest is the request body for POST /auth/login.
type LoginRequest struct {
	Email          string `json:"email" binding:"required,email,max=150"`
	Password       string `json:"password" binding:"required,max=72"`
	RecaptchaToken string `json:"recaptcha_token" binding:"omitempty,max=4096"`
}

// ToLoginInput converts LoginRequest and client metadata to domain input.
func ToLoginInput(req LoginRequest, meta domain.Metadata) domain.LoginInput {
	meta.RecaptchaToken = req.RecaptchaToken
	return domain.LoginInput{Email: req.Email, Password: req.Password, Metadata: meta}
}

// RefreshRequest is the request body for POST /auth/refresh.
type RefreshRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required,max=512"`
}

// TokenRequest is the request body for the internal token endpoints.
type TokenRequest struct {
	Token string `json:"token" binding:"required,max=512"`
}

// TokenPairResponse represents the JSON response for an issued token pair.
type TokenPairResponse struct {
	AccessToken      string `json:"access_token"`
	RefreshToken     string `json:"refresh_token"`
	TokenType        string `json:"token_type"`
	ExpiresIn        int64  `json:"expires_in"`
	RefreshExpiresIn int64  `json:"refresh_expires_in"`
}

// NewTokenPairResponse converts domain.TokenPair to TokenPairResponse; lifetimes are in seconds.
func NewTokenPairResponse(p *domain.TokenPair, now time.Time) TokenPairResponse {
	return TokenPairResponse{
		AccessToken:      p.AccessToken,
		RefreshToken:     p.RefreshToken,
		TokenType:        "Bearer",
		ExpiresIn:        int64(p.AccessExpiresAt.Sub(now).Seconds()),
		RefreshExpiresIn: int64(p.RefreshExpiresAt.Sub(now).Seconds()),
	}
}

// UserInfo is the user part of a session response.
type UserInfo struct {
	UUID      uuid.UUID `json:"uuid"`
	Email     string    `json:"email"`
	FirstName string    `json:"first_name"`
	LastName  string    `json:"last_name"`
	AvatarURL *string   `json:"avatar_url"`
	Active    bool      `json:"active"`
}

// SessionInfo is the client/session part of a session response.
type SessionInfo struct {
	FamilyUUID uuid.UUID `json:"family_uuid"`
	IPAddress  *string   `json:"ip_address"`
	UserAgent  *string   `json:"user_agent"`
	DeviceID   *string   `json:"device_id"`
	CreatedAt  time.Time `json:"created_at"`
}

// TokenInfo describes one token of a session. Token hashes are never exposed.
type TokenInfo struct {
	UUID      uuid.UUID  `json:"uuid"`
	ExpiresAt time.Time  `json:"expires_at"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
	Status    string     `json:"status"`
}

// SessionResponse represents a session with its user and tokens (GET /auth/me, token details).
type SessionResponse struct {
	User         UserInfo    `json:"user"`
	Session      SessionInfo `json:"session"`
	AccessToken  TokenInfo   `json:"access_token"`
	RefreshToken TokenInfo   `json:"refresh_token"`
}

// NewSessionResponse converts domain.Session to SessionResponse.
func NewSessionResponse(s *domain.Session, now time.Time) SessionResponse {
	return SessionResponse{
		User: UserInfo{
			UUID:      s.UserUUID,
			Email:     s.Email,
			FirstName: s.FirstName,
			LastName:  s.LastName,
			AvatarURL: s.AvatarURL,
			Active:    s.UserActive,
		},
		Session: SessionInfo{
			FamilyUUID: s.FamilyUUID,
			IPAddress:  s.IPAddress,
			UserAgent:  s.UserAgent,
			DeviceID:   s.DeviceID,
			CreatedAt:  s.CreatedAt,
		},
		AccessToken:  newTokenInfo(s.Access, now),
		RefreshToken: newTokenInfo(s.Refresh, now),
	}
}

// MeResponse represents the JSON response for GET /auth/me: the session and the permission codes
// the user holds, for the UI to show what they may do (the server still checks every request).
type MeResponse struct {
	SessionResponse
	Permissions []string `json:"permissions"`
}

// NewMeResponse converts a session and the user's permissions to MeResponse.
func NewMeResponse(s *domain.Session, permissions []string, now time.Time) MeResponse {
	if permissions == nil {
		permissions = []string{}
	}

	return MeResponse{SessionResponse: NewSessionResponse(s, now), Permissions: permissions}
}

// TokenDetailsResponse represents the JSON response for POST /internal/auth/token-details.
type TokenDetailsResponse struct {
	TokenType   string `json:"token_type"`
	TokenStatus string `json:"token_status"`
	SessionResponse
}

// NewTokenDetailsResponse converts domain.TokenDetails to TokenDetailsResponse.
func NewTokenDetailsResponse(d *domain.TokenDetails, now time.Time) TokenDetailsResponse {
	return TokenDetailsResponse{
		TokenType:       d.TokenType.String(),
		TokenStatus:     d.Status,
		SessionResponse: NewSessionResponse(d.Session, now),
	}
}

// SessionSummaryResponse represents one entry of GET /auth/sessions.
type SessionSummaryResponse struct {
	FamilyUUID uuid.UUID  `json:"family_uuid"`
	IPAddress  *string    `json:"ip_address"`
	UserAgent  *string    `json:"user_agent"`
	DeviceID   *string    `json:"device_id"`
	CreatedAt  time.Time  `json:"created_at"`
	UpdatedAt  *time.Time `json:"updated_at,omitempty"`
	ExpiresAt  time.Time  `json:"expires_at"`
	Current    bool       `json:"current"`
}

// NewSessionSummaryResponseList converts a slice of domain.SessionSummary to its response list.
func NewSessionSummaryResponseList(items []*domain.SessionSummary) []SessionSummaryResponse {
	responses := make([]SessionSummaryResponse, len(items))
	for i, m := range items {
		responses[i] = SessionSummaryResponse{
			FamilyUUID: m.FamilyUUID,
			IPAddress:  m.IPAddress,
			UserAgent:  m.UserAgent,
			DeviceID:   m.DeviceID,
			CreatedAt:  m.CreatedAt,
			UpdatedAt:  m.UpdatedAt,
			ExpiresAt:  m.ExpiresAt,
			Current:    m.Current,
		}
	}

	return responses
}

// newTokenInfo converts domain.TokenState to TokenInfo.
func newTokenInfo(t domain.TokenState, now time.Time) TokenInfo {
	return TokenInfo{UUID: t.UUID, ExpiresAt: t.ExpiresAt, RevokedAt: t.RevokedAt, Status: t.Status(now)}
}
