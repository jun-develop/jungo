package main

// =============================================================================
// TEST CASE OVERVIEW
// =============================================================================
//
// File: templates_test.go
// Purpose: Verify that generated test files get an aligned Test Case Overview.
// Type: Unit
//
// Test functions: 2
// Total scenarios: 4
//
// #  Test Case                                 Scenario                          Expected Result
// 1  TestAlignOverview_PadsColumns             Rows with names of other lengths  Every column starts at the same offset
// 2  TestAlignOverview_PadsColumns             Text without an overview          Returned unchanged
// 3  TestAlignOverview_PadsColumns             Row missing a column              Returned unchanged
// 4  TestFill_AlignsOverviewForTheFeatureName  Service test template, long name  Overview aligned for the real test names
//
// =============================================================================

import (
	"strings"
	"testing"

	"github.com/jun-develop/junkit/scaffold"
)

func TestAlignOverview_PadsColumns(t *testing.T) {
	tests := []struct {
		name string
		text string
		want string
	}{
		{
			name: "rows with names of other lengths",
			text: "// #  Test Case  Scenario  Expected Result\n" +
				"// 1  TestA_Long  One  Works\n" +
				"// 2  TestB  Another one  Fails",
			want: "// #  Test Case   Scenario     Expected Result\n" +
				"// 1  TestA_Long  One          Works\n" +
				"// 2  TestB       Another one  Fails",
		},
		{
			name: "text without an overview",
			text: "package service\n\nfunc main() {}\n",
			want: "package service\n\nfunc main() {}\n",
		},
		{
			name: "row missing a column",
			text: "// #  Test Case  Scenario  Expected Result\n// 1  TestA  Works",
			want: "// #  Test Case  Scenario  Expected Result\n// 1  TestA  Works",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := alignOverview(tt.text); got != tt.want {
				t.Errorf("alignOverview() =\n%s\nwant\n%s", got, tt.want)
			}
		})
	}
}

func TestFill_AlignsOverviewForTheFeatureName(t *testing.T) {
	data := scaffold.FeatureData{Name: "order_item", Pascal: "OrderItem", Plural: "order_items"}

	got := fill(serviceTestTmpl, data)

	var rows []string
	for _, line := range strings.Split(got, "\n") {
		if overviewHeader.MatchString(line) || overviewRow.MatchString(line) {
			rows = append(rows, line)
		}
	}

	if len(rows) != 7 {
		t.Fatalf("overview has %d lines, want the header and 6 rows", len(rows))
	}

	scenarioColumn := strings.Index(rows[0], "Scenario")
	for _, row := range rows[1:] {
		if gap := row[scenarioColumn-2 : scenarioColumn]; gap != "  " {
			t.Errorf("row %q: %q before column %d, want the two-space column gap", row, gap, scenarioColumn)
		}

		if row[scenarioColumn] == ' ' {
			t.Errorf("row %q: scenario does not start at column %d", row, scenarioColumn)
		}
	}
}
