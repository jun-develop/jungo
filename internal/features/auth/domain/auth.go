package domain

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// TokenType distinguishes the two tokens of a session.
type TokenType int16

// Token type constants (auth_tokens.type).
const (
	TokenTypeAccess  TokenType = 1
	TokenTypeRefresh TokenType = 2
)

// String returns the token type name used in API responses.
func (t TokenType) String() string {
	switch t {
	case TokenTypeAccess:
		return "access_token"
	case TokenTypeRefresh:
		return "refresh_token"
	default:
		return "unknown"
	}
}

// Revocation reasons (auth_tokens.revoked_reason).
const (
	RevokedReasonLogout       = "logout"
	RevokedReasonRefresh      = "refresh"
	RevokedReasonReuse        = "reuse"
	RevokedReasonAdmin        = "admin"
	RevokedReasonUserDisabled = "user_disabled"
)

// Refresh outcomes reported by RefreshSession (f_auth_refresh_session).
const (
	RefreshRotated      = "rotated"
	RefreshNotFound     = "not_found"
	RefreshInvalidType  = "invalid_type"
	RefreshUserInactive = "user_inactive"
	RefreshReused       = "reused"
	RefreshRevoked      = "revoked"
	RefreshExpired      = "expired"
)

// Token status values reported by GetTokenDetails.
const (
	TokenStatusActive  = "active"
	TokenStatusExpired = "expired"
	TokenStatusRevoked = "revoked"
)

// TokenState is the stored state of one token of a session.
type TokenState struct {
	UUID      uuid.UUID
	Hash      string
	ExpiresAt time.Time
	RevokedAt *time.Time
}

// Status reports whether the token is active, expired or revoked at now.
func (t TokenState) Status(now time.Time) string {
	switch {
	case t.RevokedAt != nil:
		return TokenStatusRevoked
	case !now.Before(t.ExpiresAt):
		return TokenStatusExpired
	default:
		return TokenStatusActive
	}
}

// Session is one login session (token family): its user and latest token pair.
type Session struct {
	UserID     int64
	UserUUID   uuid.UUID
	Email      string
	FirstName  string
	LastName   string
	AvatarURL  *string
	UserActive bool

	FamilyUUID uuid.UUID
	IPAddress  *string
	UserAgent  *string
	DeviceID   *string
	CreatedAt  time.Time

	Access  TokenState
	Refresh TokenState

	Permissions []string `json:"-"`
}

// Identity is the authenticated principal attached to a request by the auth middleware.
type Identity struct {
	UserID     int64
	UserUUID   uuid.UUID
	Email      string
	FamilyUUID uuid.UUID
	TokenUUID  uuid.UUID
	ExpiresAt  time.Time

	// Session is the session the access token belongs to (for /auth/me).
	Session *Session
}

// SubjectID implements middleware.Subject.
func (i *Identity) SubjectID() int64 {
	return i.UserID
}

// SubjectUUID implements middleware.Subject.
func (i *Identity) SubjectUUID() uuid.UUID {
	return i.UserUUID
}

// Permissions implements middleware.PermissionCarrier. ok is false when the session came from the
// cache: the Guard then loads the codes itself, through the permission cache.
func (i *Identity) Permissions() (codes []string, ok bool) {
	if i.Session == nil || i.Session.Permissions == nil {
		return nil, false
	}

	return i.Session.Permissions, true
}

// TokenDetails describes a token for internal (service-to-service) inspection.
type TokenDetails struct {
	Session   *Session
	TokenType TokenType
	Status    string
}

// StoredToken is a single auth_tokens row with its owner's status.
type StoredToken struct {
	UUID          uuid.UUID
	UserID        int64
	UserUUID      uuid.UUID
	UserActive    bool
	FamilyUUID    uuid.UUID
	Type          TokenType
	DeviceID      *string
	ExpiresAt     time.Time
	RevokedAt     *time.Time
	RevokedReason *string
}

// SessionSummary is one active session in the user's session list.
type SessionSummary struct {
	FamilyUUID uuid.UUID
	IPAddress  *string
	UserAgent  *string
	DeviceID   *string
	CreatedAt  time.Time
	UpdatedAt  *time.Time
	ExpiresAt  time.Time
	Current    bool
}

// Credentials is the login view of a user.
type Credentials struct {
	UserID       int64
	UserUUID     uuid.UUID
	PasswordHash string
	Active       bool
}

// Metadata describes the client making an auth request.
type Metadata struct {
	IPAddress      string
	UserAgent      string
	DeviceID       string
	RecaptchaToken string
}

// LoginInput holds data for Login.
type LoginInput struct {
	Email    string
	Password string
	Metadata Metadata
}

// TokenPair is the sealed token pair returned to the client.
type TokenPair struct {
	AccessToken      string
	RefreshToken     string
	AccessExpiresAt  time.Time
	RefreshExpiresAt time.Time
}

// NewSessionParams holds the hashed token pair and client metadata to persist. RefreshSession
// ignores UserID and FamilyUUID: it takes them from the refresh token.
type NewSessionParams struct {
	UserID           int64
	FamilyUUID       uuid.UUID
	AccessHash       string
	AccessExpiresAt  time.Time
	RefreshHash      string
	RefreshExpiresAt time.Time
	IPAddress        *string
	UserAgent        *string
	DeviceID         *string
}

// LoginSessionResult reports what CreateLoginSession did.
type LoginSessionResult struct {
	FamilyUUID uuid.UUID

	// StaleFamilyUUID is the rotated or replaced family to invalidate (uuid.Nil if none).
	StaleFamilyUUID uuid.UUID
}

// RefreshResult reports what RefreshSession did.
type RefreshResult struct {
	Status     string
	FamilyUUID uuid.UUID
	UserUUID   uuid.UUID
}

// UserProvider reads users for authentication; implemented by an adapter over the user feature.
type UserProvider interface {
	GetCredentialsByEmail(ctx context.Context, email string) (*Credentials, error)
}

// AuthRepository defines database operations for auth tokens.
type AuthRepository interface {
	CreateLoginSession(ctx context.Context, params NewSessionParams) (*LoginSessionResult, error)
	RefreshSession(ctx context.Context, hash string, params NewSessionParams) (*RefreshResult, error)
	GetSessionByHash(ctx context.Context, hash string) (*Session, error)
	GetTokenByHash(ctx context.Context, hash string) (*StoredToken, error)
	RevokeFamily(ctx context.Context, familyUUID uuid.UUID, reason string) error
	RevokeFamilyByHash(ctx context.Context, hash, reason string) (uuid.UUID, error)
	RevokeAllByHash(ctx context.Context, hash, reason string) ([]uuid.UUID, error)
	RevokeAllForUser(ctx context.Context, userUUID uuid.UUID, reason string) ([]uuid.UUID, error)
	ListActiveSessions(ctx context.Context, userID int64) ([]*SessionSummary, error)
	CleanupTokens(ctx context.Context, before time.Time) (int64, error)
}

// SessionCache caches sessions by token hash.
type SessionCache interface {
	GetOrLoad(ctx context.Context, hash string, load func() (*Session, error)) (*Session, error)
	InvalidateFamilies(ctx context.Context, familyUUIDs ...uuid.UUID)
}

// LoginGuard throttles failed logins per IP and per email.
type LoginGuard interface {
	Attempt(ctx context.Context, ip, email string) (int64, error)
	RecordFailure(ctx context.Context, ip string)
	Succeeded(ctx context.Context, ip, email string)
}

// AuthService defines business logic for authentication.
type AuthService interface {
	Login(ctx context.Context, input LoginInput) (*TokenPair, error)
	Refresh(ctx context.Context, refreshToken string, meta Metadata) (*TokenPair, error)
	Logout(ctx context.Context, identity *Identity) error
	LogoutAll(ctx context.Context, identity *Identity) error
	AuthenticateAccess(ctx context.Context, token string) (*Identity, error)
	ListSessions(ctx context.Context, identity *Identity) ([]*SessionSummary, error)
	GetTokenDetails(ctx context.Context, token string) (*TokenDetails, error)
	RevokeToken(ctx context.Context, token string) error
	RevokeAllTokens(ctx context.Context, token string) error
	CleanupTokens(ctx context.Context, retention time.Duration) (int64, error)
}
