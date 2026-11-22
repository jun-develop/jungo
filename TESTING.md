# Jungo test standard

Every `*_test.go` file in Jungo follows the rules below (the same standard as Junkit). The goal: a
reader understands what a file verifies without opening the production code.

Tests focus on the service layer (`internal/features/<feature>/service`). Services are tested
against hand-written in-memory fakes of their repositories and adapters; repositories (SQL) are not
unit-tested.

## 1. File layout

1. `package` clause.
2. Header block (Test Case Overview, or Test Helpers block for helper-only files).
3. Imports.
4. Shared constants and fixtures used by several tests in the file.
5. Helper functions (`t.Helper()` first line).
6. Test functions, grouped by the service method under test.

Service tests live in `package service` (they need unexported fields). Fakes shared by the tests of
a package live in that package's `fakes_test.go`, which has a `TEST HELPERS` block instead of an
overview.

## 2. Test Case Overview

Placed right after the `package` clause. Columns are separated by at least two spaces and
aligned. One row per scenario, in source order.

```go
package service

// =============================================================================
// TEST CASE OVERVIEW
// =============================================================================
//
// File: user_service_test.go
// Purpose: Verify user management: creation, lookup, updates, deletion and avatars.
// Type: Unit (in-memory fakes)
//
// Test functions: 2
// Total scenarios: 3
//
// #  Test Case                                  Scenario                   Expected Result
// 1  TestUserService_CreateUser_StoresNewUser   New email                  User created with a hashed password
// 2  TestUserService_CreateUser_StoresNewUser   Email already used         Returns ErrEmailTaken
// 3  TestUserService_GetUser_ReturnsUser        Unknown UUID               Returns ErrUserNotFound
//
// =============================================================================
```

- `Type:` is `Unit` or `Integration (<what it needs>)`.
- Helper-only files (no `Test` functions) use a `TEST HELPERS` block with `File`, `Purpose` and
  `Used by` lines. They never get a fake overview.

## 3. Counting

- **Test functions** = top-level `func TestXxx(t *testing.T)`.
- **Scenario** = one leaf test run, i.e. what `go test -v` reports as a test that has no
  subtests. A test without `t.Run` is one scenario. A table with five cases is five scenarios.
  Subtests that only group other subtests are not counted.

## 4. Naming

- Top-level: `Test<Service>_<Method>_<Behavior>`, e.g.
  `TestAuthService_Refresh_ReuseRevokesWholeSession`. Never `TestSuccess`, `TestError`,
  or a bare method name such as `TestUserService_GetUser`.
- Subtests and table cases: short lower-case phrases describing the scenario, e.g.
  `"actor without users:manage"`. Not raw input values when the input alone does not explain it.
- Table slices use `tests` and the loop variable `tt`. Use slices, not maps, so order is stable.

## 5. Body

- Arrange, Act, Assert, in that order. Add the three comments only when the test is long enough
  that they help.
- Each scenario states its input and expected result explicitly (`want`, `wantErr`, ...).
- Assertion messages follow `Func(input) = got, want want`. One condition per assertion, so a
  failure says exactly what was wrong.
- Never ignore an error from setup: `if err != nil { t.Fatalf("setup: %v", err) }`.
- Use `t.Fatalf` when continuing makes no sense, `t.Errorf` otherwise.
- Use a table only when cases share setup, action and assertions. Otherwise write separate tests.

## 6. Helpers, fakes and isolation

- Extract a helper only when it removes real noise and its name says what it does.
- Fakes are small hand-written types. No mocking frameworks.
- Clean up with `t.Cleanup`. Use `t.TempDir`, `t.Setenv`. No test depends on another test
  running first.

## 7. Keeping overviews correct

When adding, removing or renaming a test or a table case, update the overview rows and both
counts in the same change. `go test -v ./<pkg> -run '<TestName>'` lists the leaf runs to compare.

CI (`.github/workflows/test.yml`) runs on every push and pull request: `gofmt`, `go vet`,
`go test -race`, then `.github/scripts/check_test_overview.py`, which fails the build when a test
fails or an overview disagrees with the tests that ran. Run the same check locally:

```sh
go test -count=1 -race -json ./... > test.json; python3 .github/scripts/check_test_overview.py test.json
```
