package service

// =============================================================================
// TEST HELPERS (no test scenarios)
// =============================================================================
//
// File: fakes_test.go
// Purpose: Func-field fake of AuditService's repository.
// Used by: audit_service_test.go
//
// =============================================================================

import (
	"context"
	"time"

	"jungo/internal/features/audit/domain"
)

// fakeAuditRepository is a domain.AuditRepository whose answers each test sets through the Func
// fields. Calling a method whose Func is nil panics, so a test sets exactly the calls it expects.
type fakeAuditRepository struct {
	CreateFunc      func(ctx context.Context, entry *domain.AuditLog) error
	ListFunc        func(ctx context.Context, filter domain.AuditLogListFilter) ([]*domain.AuditLog, int64, error)
	CleanupLogsFunc func(ctx context.Context, before time.Time) (int64, error)
}

// Create answers through CreateFunc.
func (f *fakeAuditRepository) Create(ctx context.Context, entry *domain.AuditLog) error {
	return f.CreateFunc(ctx, entry)
}

// List answers through ListFunc.
func (f *fakeAuditRepository) List(ctx context.Context, filter domain.AuditLogListFilter) ([]*domain.AuditLog, int64, error) {
	return f.ListFunc(ctx, filter)
}

// CleanupLogs answers through CleanupLogsFunc.
func (f *fakeAuditRepository) CleanupLogs(ctx context.Context, before time.Time) (int64, error) {
	return f.CleanupLogsFunc(ctx, before)
}
