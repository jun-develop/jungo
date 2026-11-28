package service

// =============================================================================
// TEST CASE OVERVIEW
// =============================================================================
//
// File: role_code_pattern_test.go
// Purpose: Verify the API docs show the role code pattern CreateRole checks.
// Type: Unit
//
// Test functions: 1
// Total scenarios: 1
//
// #  Test Case                        Scenario                            Expected Result
// 1  TestRoleCodePattern_MatchesDocs  pattern tag of CreateRoleRequest.code  Equals roleCodePattern
//
// =============================================================================

import (
	"reflect"
	"testing"

	v1dto "jungo/internal/features/access/dto/v1"
)

// The API docs show CreateRoleRequest.code's pattern tag; it must be the regex CreateRole checks.
func TestRoleCodePattern_MatchesDocs(t *testing.T) {
	f, _ := reflect.TypeFor[v1dto.CreateRoleRequest]().FieldByName("Code")
	if got := f.Tag.Get("pattern"); got != roleCodePattern.String() {
		t.Errorf("CreateRoleRequest.Code pattern tag = %q, want %q", got, roleCodePattern.String())
	}
}
