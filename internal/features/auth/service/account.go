package service

import (
	"context"

	"github.com/google/uuid"

	"github.com/jun-develop/junkit/tracer"

	"jungo/internal/common/auditlog"
	"jungo/internal/features/auth/domain"
)

// LogoutOthers ends every session of the identity's user but the one it belongs to.
func (s *AuthService) LogoutOthers(ctx context.Context, identity *domain.Identity) error {
	families, err := s.repo.RevokeOtherSessions(ctx, identity.UserID, identity.FamilyUUID, domain.RevokedReasonLogout)
	if err != nil {
		return err
	}

	s.cache.InvalidateFamilies(ctx, families...)

	return nil
}

// RevokeSession ends one of the identity's user's own active sessions; ending the one the identity
// belongs to is a logout. Another user's session, or one that does not exist or has ended, is
// ErrSessionNotFound, so the answer does not reveal other users' sessions.
func (s *AuthService) RevokeSession(ctx context.Context, identity *domain.Identity, familyUUID uuid.UUID) error {
	if err := s.repo.RevokeUserSession(ctx, identity.UserID, familyUUID, domain.RevokedReasonLogout); err != nil {
		return err
	}

	s.cache.InvalidateFamilies(ctx, familyUUID)

	return nil
}

// ChangePassword sets a new password for the identity's user once their current one is verified,
// then ends their other sessions and keeps this one. Wrong current passwords count as failed logins
// from the client's IP, so a stolen access token cannot be used to guess the password.
//
// Flow: check length -> reserve attempt -> verify current -> [save hash -> revoke other sessions -> audit] (tx) -> drop cached sessions
func (s *AuthService) ChangePassword(ctx context.Context, identity *domain.Identity, input domain.ChangePasswordInput) error {
	if len(input.NewPassword) > maxPasswordBytes {
		return domain.ErrPasswordTooLong
	}

	ip := input.Metadata.IPAddress
	if _, err := s.guard.Attempt(ctx, ip); err != nil {
		return err
	}

	creds, err := s.users.GetCredentialsByEmail(ctx, identity.Email)
	if err != nil {
		return err
	}

	stop := tracer.Span(ctx, "Bcrypt Compare")
	valid, err := s.hasher.Compare(ctx, creds.PasswordHash, input.CurrentPassword)
	stop()
	if err != nil {
		return err
	}

	if !valid {
		s.guard.RecordFailure(ctx, ip)
		return domain.ErrInvalidCurrentPassword
	}

	s.guard.RecordSuccess(ctx, ip)

	if input.NewPassword == input.CurrentPassword {
		return domain.ErrNewPasswordSameAsCurrent
	}

	stop = tracer.Span(ctx, "Bcrypt Hashing")
	hash, err := s.hasher.Hash(ctx, input.NewPassword)
	stop()
	if err != nil {
		return err
	}

	var families []uuid.UUID
	err = s.repo.WithTransaction(ctx, func(ctx context.Context) error {
		if err := s.users.SetPasswordHash(ctx, creds.UserID, hash); err != nil {
			return err
		}

		if families, err = s.repo.RevokeOtherSessions(ctx, creds.UserID, identity.FamilyUUID, domain.RevokedReasonPasswordChange); err != nil {
			return err
		}

		return s.audit.Record(ctx, auditlog.Entry{Action: domain.ActionChangePassword, EntityType: "users", EntityID: creds.UserUUID.String()})
	})
	if err != nil {
		return err
	}

	s.cache.InvalidateFamilies(ctx, families...)

	return nil
}
