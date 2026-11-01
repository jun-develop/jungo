// Command scaffold generates or removes feature modules and CLI commands.
//
// Usage:
//
//	make feature NAME=product
//	make feature-remove NAME=product
//	make command NAME=health-check SIGNATURE=health:check
//	make command NAME=list-users SIGNATURE=user:list FEATURE=user
package main

import (
	"flag"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/jun-develop/junkit/console"
	"github.com/jun-develop/junkit/scaffold"
)

const (
	moduleName    = "jungo"
	featuresDir   = "internal/features"
	fxFile        = "internal/app/fx.go"
	featureMarker = "// FEATURES"
	migrationsDir = "internal/database/primary/migrations"
	queriesDir    = "internal/database/primary/queries"
	sqlcDir       = "internal/database/primary/sqlc"
)

// featureNamePattern also keeps the permission codes ("<plural>:read") within chk_permissions_code_format.
var featureNamePattern = regexp.MustCompile(`^[a-z][a-z_]*$`)

func main() {
	kind := flag.String("type", "feature", "\"feature\" or \"command\"")
	name := flag.String("name", "", "Name in snake_case (required)")
	mode := flag.String("mode", "create", "\"create\" or \"remove\" (feature only)")
	table := flag.String("table", "", "Override the generated table name (feature only, default: \"<name>s\")")
	signature := flag.String("signature", "", "CLI signature, e.g. \"user:list\" (command only, required)")
	feature := flag.String("feature", "", "Attach the command to this existing feature instead of internal/console/commands (command only)")
	flag.Parse()

	switch *kind {
	case "feature":
		runFeatureScaffold(*name, *mode, *table)
	case "command":
		runCommandScaffold(*name, *signature, *feature)
	default:
		console.Fatalf("unknown -type %q: use \"feature\" or \"command\"", *kind)
	}
}

// runFeatureScaffold validates the feature name and dispatches to create or remove.
func runFeatureScaffold(name, mode, table string) {
	if name == "" {
		console.Fatalf("feature name is required. Usage: make feature NAME=<feature_name>")
	}

	if !featureNamePattern.MatchString(name) {
		console.Fatalf("invalid feature name %q: must be snake_case (lowercase letters and underscores; must start with a letter)", name)
	}

	data := scaffold.NewFeatureData(name, moduleName, table)
	importPath := fmt.Sprintf("%s/internal/features/%s", moduleName, data.Name)
	moduleLine := fmt.Sprintf("%s.Module,", data.Name)

	switch mode {
	case "create":
		runCreate(data, importPath, moduleLine)
	case "remove":
		runRemove(data, importPath, moduleLine)
	default:
		console.Fatalf("unknown mode %q: use \"create\" or \"remove\"", mode)
	}
}

// runCreate generates a feature and registers its module in fx.go.
func runCreate(data scaffold.FeatureData, importPath, moduleLine string) {
	featureDir := filepath.Join(featuresDir, data.Name)

	seq, err := scaffold.NextMigrationSeq(migrationsDir)
	if err != nil {
		console.Fatalf("compute next migration sequence: %v", err)
	}

	console.Infof("Generating feature %q (table %q, migration %s)...", data.Name, data.Table, seq)

	cfg := scaffold.GenerateConfig{
		Data:       data,
		Files:      featureFiles(data, seq),
		FxFile:     fxFile,
		ImportPath: importPath,
		Marker:     featureMarker,
		ModuleLine: moduleLine,
	}

	if err := scaffold.Generate(cfg); err != nil {
		console.Fatalf("generate feature %q: %v", data.Name, err)
	}

	console.Successf("Feature %q generated in %s", data.Name, featureDir)
	console.Infof("Next: make migrate-up   (creates the %s table and its %s:* permissions, granted to super_admin)", data.Table, data.Plural)
	console.Infof("Then: make sqlc         (generates internal/database/primary/sqlc/%s.sql.go)", data.Name)
	console.Infof("Then: go build ./...    (verify everything compiles)")
}

// runRemove deletes a feature's files and unregisters its module from fx.go.
func runRemove(data scaffold.FeatureData, importPath, moduleLine string) {
	cfg := scaffold.RemoveConfig{
		Dirs: []string{filepath.Join(featuresDir, data.Name)},
		ExtraFiles: []string{
			filepath.Join(sqlcDir, data.Name+".sql.go"),
			filepath.Join(queriesDir, data.Name+".sql"),
		},
		FxFile:     fxFile,
		ImportPath: importPath,
		ModuleLine: moduleLine,
	}

	if err := scaffold.Remove(cfg); err != nil {
		console.Fatalf("remove feature %q: %v", data.Name, err)
	}

	upFiles, _ := filepath.Glob(filepath.Join(migrationsDir, "*_"+data.Table+".up.sql"))
	downFiles, _ := filepath.Glob(filepath.Join(migrationsDir, "*_"+data.Table+".down.sql"))
	migrationFiles := append(upFiles, downFiles...)
	if len(migrationFiles) == 0 {
		migrationFiles = []string{
			filepath.Join(migrationsDir, "NNNNNN_"+data.Table+".up.sql"),
			filepath.Join(migrationsDir, "NNNNNN_"+data.Table+".down.sql"),
		}
	}

	console.Warnf("Dropping a table is destructive, so finish the database cleanup by hand:")
	console.Infof("1. make migrate-down            — rolls back the last migration, dropping the %q table and its permissions from your database", data.Table)
	console.Infof("2. rm %s   — deletes the now-orphaned migration files", strings.Join(migrationFiles, " "))
	console.Infof("3. make sqlc                     — regenerates internal/database/primary/sqlc so %q is removed from models.go", data.Model)

	console.Successf("Feature %q removed", data.Name)
}
