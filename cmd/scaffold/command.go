package main

import (
	"fmt"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/jun-develop/junkit/console"
	"github.com/jun-develop/junkit/scaffold"
)

const (
	consolePkg    = "jungo/internal/console"
	globalCmdDir  = "internal/console/commands"
	globalCmdFile = globalCmdDir + "/module.go"
	commandMarker = "// COMMANDS"
)

// commandData is the template context for a generated command file.
type commandData struct {
	Pascal    string
	Signature string
	Package   string
}

// runCommandScaffold generates and registers a CLI command (global or feature-scoped).
func runCommandScaffold(name, signature, featureName string) {
	if name == "" {
		console.Fatalf("command name is required. Usage: make command NAME=<name> SIGNATURE=<cli:signature>")
	}

	if !commandNamePattern.MatchString(name) || token.IsKeyword(name) {
		console.Fatalf("invalid command name %q: must be snake_case (lowercase letters, digits, underscores; must start with a letter) and not a Go keyword", name)
	}

	if signature == "" {
		console.Fatalf("-signature is required, e.g. -signature %q", strings.ReplaceAll(name, "_", ":"))
	}

	pascal := scaffold.NewFeatureData(name, moduleName, "").Pascal

	if featureName == "" {
		generateGlobalCommand(name, pascal, signature)
		return
	}

	generateFeatureCommand(featureName, name, pascal, signature)
}

// generateGlobalCommand creates and registers a global CLI command.
func generateGlobalCommand(name, pascal, signature string) {
	filePath := filepath.Join(globalCmdDir, name+"_command.go")
	data := commandData{Pascal: pascal, Signature: signature, Package: "commands"}

	requireMarker(globalCmdFile, commandMarker)
	writeCommandFile(filePath, data)

	block := commandRegistrationBlock(fmt.Sprintf("New%sCommand", pascal))
	if err := insertAfterMarker(globalCmdFile, commandMarker, block); err != nil {
		console.Fatalf("register command in %s: %v", globalCmdFile, err)
	}

	gofmtPaths(filePath, globalCmdFile)

	console.Successf("Command %q generated in %s", signature, filePath)
	console.Infof("Run it with: make console CMD=%q", signature)
}

// generateFeatureCommand creates and registers a feature-scoped CLI command.
func generateFeatureCommand(featureName, name, pascal, signature string) {
	featureDir := filepath.Join(featuresDir, featureName)
	if _, err := os.Stat(featureDir); err != nil {
		console.Fatalf("feature %q not found at %s — scaffold it first with: make feature NAME=%s", featureName, featureDir, featureName)
	}

	moduleFile := filepath.Join(featureDir, "module.go")
	filePath := filepath.Join(featureDir, "command", name+"_command.go")
	data := commandData{Pascal: pascal, Signature: signature, Package: "command"}

	requireMarker(moduleFile, commandMarker)
	writeCommandFile(filePath, data)

	commandImport := fmt.Sprintf("%s/internal/features/%s/command", moduleName, featureName)
	if err := insertImportLineIfMissing(moduleFile, consolePkg); err != nil {
		console.Fatalf("register command import in %s: %v", moduleFile, err)
	}

	if err := insertImportLineIfMissing(moduleFile, commandImport); err != nil {
		console.Fatalf("register command import in %s: %v", moduleFile, err)
	}

	block := commandRegistrationBlock(fmt.Sprintf("command.New%sCommand", pascal))
	if err := insertAfterMarker(moduleFile, commandMarker, block); err != nil {
		console.Fatalf("register command in %s: %v", moduleFile, err)
	}

	gofmtPaths(filePath, moduleFile)

	console.Successf("Command %q generated in %s", signature, filePath)
	console.Infof("Run it with: make console CMD=%q", signature)
}

// requireMarker stops before anything is written when path lacks marker, so a failed registration never leaves a half-generated command behind.
func requireMarker(path, marker string) {
	content, err := os.ReadFile(path)
	if err != nil {
		console.Fatalf("read %s: %v", path, err)
	}

	if !strings.Contains(string(content), marker) {
		console.Fatalf("%s has no %q marker to register the command after; add it inside the module's options", path, marker)
	}
}

// writeCommandFile renders the command template to path without overwriting existing files.
func writeCommandFile(path string, data commandData) {
	if _, err := os.Stat(path); err == nil {
		console.Fatalf("%s already exists — refusing to overwrite", path)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		console.Fatalf("create directory for %s: %v", path, err)
	}

	tmpl, err := template.New(path).Parse(commandStubTmpl)
	if err != nil {
		console.Fatalf("parse command template: %v", err)
	}

	file, err := os.Create(path)
	if err != nil {
		console.Fatalf("create %s: %v", path, err)
	}

	defer file.Close()

	if err := tmpl.Execute(file, data); err != nil {
		console.Fatalf("render %s: %v", path, err)
	}

	console.Successf("Created %s", path)
}

// commandRegistrationBlock builds the fx.Provide block for the "commands" group.
func commandRegistrationBlock(constructorRef string) []string {
	return []string{
		"\t\tfx.Provide(",
		"\t\t\tfx.Annotate(",
		"\t\t\t\t" + constructorRef + ",",
		"\t\t\t\tfx.As(new(console.Command)),",
		"\t\t\t\tfx.ResultTags(`group:\"commands\"`),",
		"\t\t\t),",
		"\t\t),",
	}
}

// insertAfterMarker inserts lines after the specified marker in path.
func insertAfterMarker(path, marker string, block []string) error {
	content, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}

	lines := strings.Split(string(content), "\n")

	markerAt := -1
	for i, l := range lines {
		if strings.Contains(l, marker) {
			markerAt = i
			break
		}
	}

	if markerAt == -1 {
		return fmt.Errorf("marker %q not found in %s", marker, path)
	}

	insertAt := markerAt + 1
	if insertAt < len(lines) && strings.Contains(lines[insertAt], "// ===") {
		insertAt++
	}

	out := make([]string, 0, len(lines)+len(block))
	out = append(out, lines[:insertAt]...)
	out = append(out, block...)
	out = append(out, lines[insertAt:]...)

	return os.WriteFile(path, []byte(strings.Join(out, "\n")), 0o644)
}

// insertImportLineIfMissing adds an import path to path if not already present.
func insertImportLineIfMissing(path, importPath string) error {
	content, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}

	if strings.Contains(string(content), "\""+importPath+"\"") {
		return nil
	}

	lines := strings.Split(string(content), "\n")

	anchor := -1
	for i, l := range lines {
		if strings.Contains(l, moduleName+"/") {
			anchor = i
		}
	}

	if anchor == -1 {
		return fmt.Errorf("no existing %q import found in %s to anchor the new import next to", moduleName, path)
	}

	out := make([]string, 0, len(lines)+1)
	out = append(out, lines[:anchor+1]...)
	out = append(out, "\t\""+importPath+"\"")
	out = append(out, lines[anchor+1:]...)

	return os.WriteFile(path, []byte(strings.Join(out, "\n")), 0o644)
}

// gofmtPaths formats the given files using gofmt.
func gofmtPaths(paths ...string) {
	if err := exec.Command("gofmt", append([]string{"-w"}, paths...)...).Run(); err != nil {
		console.Warnf("gofmt: %v", err)
	}
}

const commandStubTmpl = `package {{.Package}}

import (
	"context"

	"github.com/jun-develop/junkit/console"
)

// {{.Pascal}}Command implements console.Command.
//
// Usage:
//
//	make console CMD="{{.Signature}}"
type {{.Pascal}}Command struct{}

// New{{.Pascal}}Command creates a {{.Pascal}}Command.
func New{{.Pascal}}Command() *{{.Pascal}}Command {
	return &{{.Pascal}}Command{}
}

// Signature implements console.Command.
func (c *{{.Pascal}}Command) Signature() string {
	return "{{.Signature}}"
}

// Run implements console.Command.
func (c *{{.Pascal}}Command) Run(ctx context.Context, args []string) error {
	console.Infof("TODO: implement {{.Signature}}")
	return nil
}
`
