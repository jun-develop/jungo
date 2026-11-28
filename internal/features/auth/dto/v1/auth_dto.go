package v1

import (
	"time"

	"github.com/google/uuid"

	"github.com/jun-develop/junkit/slicex"

	"jungo/internal/common/actor"
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

// ForgotPasswordRequest is the request body for POST /auth/forgot-password.
type ForgotPasswordRequest struct {
	Email string `json:"email" binding:"required,email,max=150"`
}

// ResetPasswordRequest is the request body for POST /auth/reset-password; Token comes from the
// emailed link.
type ResetPasswordRequest struct {
	Token    string `json:"token" binding:"required,max=128"`
	Password string `json:"password" binding:"required,min=8,max=72,password_strong"`
}

// ChangePasswordRequest is the request body for POST /auth/change-password.
type ChangePasswordRequest struct {
	CurrentPassword string `json:"current_password" binding:"required,max=72"`
	NewPassword     string `json:"new_password" binding:"required,min=8,max=72,password_strong"`
}

// ToChangePasswordInput converts ChangePasswordRequest and client metadata to domain input.
func ToChangePasswordInput(req ChangePasswordRequest, meta domain.Metadata) domain.ChangePasswordInput {
	return domain.ChangePasswordInput{CurrentPassword: req.CurrentPassword, NewPassword: req.NewPassword, Metadata: meta}
}

// TokenRequest is the request body for the internal token endpoints (/api/internal/auth/*).
type TokenRequest struct {
	Token string `json:"token" binding:"required,max=512"`
}

// TokenPairResponse represents the JSON response for an issued token pair.
type TokenPairResponse struct {
	AccessToken      string `json:"access_token"`
	RefreshToken     string `json:"refresh_token"`
	TokenType        string `json:"token_type" enum:"Bearer"`
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

// SessionUserResponse is the user part of a session response.
type SessionUserResponse struct {
	UUID        uuid.UUID `json:"uuid"`
	Email       string    `json:"email"`
	FirstName   string    `json:"first_name"`
	LastName    string    `json:"last_name"`
	PhoneNumber *string   `json:"phone_number"`
	AvatarURL   *string   `json:"avatar_url"`
	Active      bool      `json:"active"`
}

// SessionClientResponse is the client/session part of a session response.
type SessionClientResponse struct {
	FamilyUUID uuid.UUID `json:"family_uuid"`
	IPAddress  *string   `json:"ip_address"`
	UserAgent  *string   `json:"user_agent"`
	DeviceID   *string   `json:"device_id"`
	CreatedAt  time.Time `json:"created_at"`
}

// TokenStateResponse describes one token of a session. Token hashes are never exposed.
type TokenStateResponse struct {
	UUID      uuid.UUID  `json:"uuid"`
	ExpiresAt time.Time  `json:"expires_at"`
	RevokedAt *time.Time `json:"revoked_at"`
	Status    string     `json:"status" enum:"active expired revoked"`
}

// SessionResponse represents a session with its user and tokens (GET /auth/me, token details).
type SessionResponse struct {
	User         SessionUserResponse   `json:"user"`
	Session      SessionClientResponse `json:"session"`
	AccessToken  TokenStateResponse    `json:"access_token"`
	RefreshToken TokenStateResponse    `json:"refresh_token"`
}

// NewSessionResponse converts domain.Session to SessionResponse.
func NewSessionResponse(s *domain.Session, now time.Time) SessionResponse {
	return SessionResponse{
		User: SessionUserResponse{
			UUID:        s.UserUUID,
			Email:       s.Email,
			FirstName:   s.FirstName,
			LastName:    s.LastName,
			PhoneNumber: s.PhoneNumber,
			AvatarURL:   s.AvatarURL,
			Active:      s.UserActive,
		},
		Session: SessionClientResponse{
			FamilyUUID: s.FamilyUUID,
			IPAddress:  s.IPAddress,
			UserAgent:  s.UserAgent,
			DeviceID:   s.DeviceID,
			CreatedAt:  s.CreatedAt,
		},
		AccessToken:  newTokenStateResponse(s.Access, now),
		RefreshToken: newTokenStateResponse(s.Refresh, now),
	}
}

// MeResponse represents the JSON response for GET /auth/me: the session and the permission codes
// the user holds, for the UI to show what they may do (the server still checks every request).
type MeResponse struct {
	SessionResponse
	Permissions []actor.PermissionCode `json:"permissions"`
}

// NewMeResponse converts a session and the user's permissions to MeResponse.
func NewMeResponse(s *domain.Session, permissions []string, now time.Time) MeResponse {
	return MeResponse{SessionResponse: NewSessionResponse(s, now), Permissions: actor.PermissionCodes(permissions)}
}

// TokenDetailsResponse represents the JSON response for POST /internal/auth/token-details.
type TokenDetailsResponse struct {
	TokenType   string `json:"token_type" enum:"access_token refresh_token"`
	TokenStatus string `json:"token_status" enum:"active expired revoked"`
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
	FamilyUUID uuid.UUID `json:"family_uuid"`
	IPAddress  *string   `json:"ip_address"`
	UserAgent  *string   `json:"user_agent"`
	DeviceID   *string   `json:"device_id"`
	CreatedAt  time.Time `json:"created_at"`
	ExpiresAt  time.Time `json:"expires_at"`
	Current    bool      `json:"current"`
}

// NewSessionSummaryResponse converts domain.SessionSummary to SessionSummaryResponse.
func NewSessionSummaryResponse(m *domain.SessionSummary) SessionSummaryResponse {
	return SessionSummaryResponse{
		FamilyUUID: m.FamilyUUID,
		IPAddress:  m.IPAddress,
		UserAgent:  m.UserAgent,
		DeviceID:   m.DeviceID,
		CreatedAt:  m.CreatedAt,
		ExpiresAt:  m.ExpiresAt,
		Current:    m.Current,
	}
}

// NewSessionSummaryResponseList converts a slice of domain.SessionSummary to its response list.
func NewSessionSummaryResponseList(items []*domain.SessionSummary) []SessionSummaryResponse {
	return slicex.Map(items, NewSessionSummaryResponse)
}

// newTokenStateResponse converts domain.TokenState to TokenStateResponse.
func newTokenStateResponse(t domain.TokenState, now time.Time) TokenStateResponse {
	return TokenStateResponse{UUID: t.UUID, ExpiresAt: t.ExpiresAt, RevokedAt: t.RevokedAt, Status: t.Status(now)}
}
