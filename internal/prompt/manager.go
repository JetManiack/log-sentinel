// Package prompt loads and renders prompt blueprints from YAML files.
//
// Embedded blueprints (internal/prompt/builtin/*.yaml) are always available.
// An optional override directory (llm.prompts_dir in config) layers on top,
// replacing built-ins by their `name` field. This lets operators customise
// prompts without recompiling the binary.
//
// Blueprint YAML format:
//
//	name: triage          # identifier; defaults to filename-without-extension
//	version: "1.0.0"
//	critical: true        # true = parse error is fatal; false = warn and skip
//	description: "..."
//	schema:               # optional: structured-output contract (json_schema)
//	  name: triage_verdict
//	  schema:
//	    type: object
//	    ...
//	system: |             # Go text/template
//	  ...
//	user: |               # Go text/template (data injected via Execute)
//	  ...
package prompt

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"text/template"

	"gopkg.in/yaml.v3"
)

//go:embed builtin
var embedded embed.FS

// schemaSpec is the optional structured-output contract of a blueprint: a JSON
// Schema (authored in YAML for readability) and a name for the response_format wrapper.
type schemaSpec struct {
	Name   string         `yaml:"name"`
	Schema map[string]any `yaml:"schema"`
}

// blueprint is a single prompt: metadata plus system/user templates.
type blueprint struct {
	Name        string     `yaml:"name"`
	Version     string     `yaml:"version"`
	Critical    bool       `yaml:"critical"`
	Description string     `yaml:"description"`
	System      string     `yaml:"system"`
	User        string     `yaml:"user"`
	Schema      schemaSpec `yaml:"schema"`

	systemTmpl *template.Template
	userTmpl   *template.Template
	schemaJSON json.RawMessage // Schema.Schema compiled to JSON; nil when absent
	schemaName string          // Schema.Name, or Name when empty
}

// Manager loads and renders prompt blueprints.
type Manager struct {
	blueprints map[string]blueprint
}

// New returns a Manager pre-loaded with embedded blueprints. If overrideDir is
// non-empty, YAML files found there override embedded ones by name. A missing
// override directory is a warning, not an error.
func New(overrideDir string) (*Manager, error) {
	m := &Manager{blueprints: make(map[string]blueprint)}
	if err := m.loadFS(embedded, "builtin"); err != nil {
		return nil, err
	}
	if overrideDir != "" {
		if err := m.loadDir(overrideDir); err != nil {
			return nil, fmt.Errorf("prompt: load override dir %q: %w", overrideDir, err)
		}
	}
	return m, nil
}

// Execute renders the named blueprint with data and returns (system, user).
func (m *Manager) Execute(name string, data any) (system, user string, err error) {
	bp, ok := m.blueprints[name]
	if !ok {
		return "", "", fmt.Errorf("prompt: blueprint %q not found", name)
	}
	system, err = render(bp.systemTmpl, data)
	if err != nil {
		return "", "", fmt.Errorf("prompt: render system for %q: %w", name, err)
	}
	user, err = render(bp.userTmpl, data)
	if err != nil {
		return "", "", fmt.Errorf("prompt: render user for %q: %w", name, err)
	}
	return system, user, nil
}

// Schema returns the structured-output JSON schema declared by the named
// blueprint, along with its schema name. ok is false when the blueprint has no
// schema (or does not exist); callers should not request json_schema output then.
func (m *Manager) Schema(name string) (raw json.RawMessage, schemaName string, ok bool) {
	bp, found := m.blueprints[name]
	if !found || bp.schemaJSON == nil {
		return nil, "", false
	}
	return bp.schemaJSON, bp.schemaName, true
}

func (m *Manager) loadFS(fsys fs.FS, root string) error {
	return fs.WalkDir(fsys, root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		if !isYAML(path) {
			return nil
		}
		data, readErr := fs.ReadFile(fsys, path)
		if readErr != nil {
			return fmt.Errorf("prompt: read %s: %w", path, readErr)
		}
		return m.parse(path, data)
	})
}

func (m *Manager) loadDir(dir string) error {
	info, err := os.Stat(dir)
	if err != nil {
		if os.IsNotExist(err) {
			slog.Warn("prompt: override dir does not exist, using built-ins only", "dir", dir)
			return nil
		}
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("prompt: override path %q is not a directory", dir)
	}
	return fs.WalkDir(os.DirFS(dir), ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path != "." && strings.HasPrefix(d.Name(), ".") {
				return fs.SkipDir
			}
			return nil
		}
		if strings.HasPrefix(filepath.Base(path), ".") || !isYAML(path) {
			return nil
		}
		data, readErr := os.ReadFile(filepath.Join(dir, path)) // #nosec G304
		if readErr != nil {
			return fmt.Errorf("prompt: read %s: %w", path, readErr)
		}
		return m.parse(path, data)
	})
}

func (m *Manager) parse(path string, data []byte) error {
	var bp blueprint
	if err := yaml.Unmarshal(data, &bp); err != nil {
		return fmt.Errorf("prompt: parse %s: %w", path, err)
	}
	if bp.Name == "" {
		base := filepath.Base(path)
		bp.Name = strings.TrimSuffix(strings.TrimSuffix(base, ".yaml"), ".yml")
	}

	var err error
	if bp.systemTmpl, err = template.New("system").Parse(bp.System); err != nil {
		if bp.Critical {
			return fmt.Errorf("prompt: invalid system template in %q: %w", bp.Name, err)
		}
		slog.Warn("prompt: invalid system template, skipping", "name", bp.Name, "err", err)
		return nil
	}
	if bp.userTmpl, err = template.New("user").Parse(bp.User); err != nil {
		if bp.Critical {
			return fmt.Errorf("prompt: invalid user template in %q: %w", bp.Name, err)
		}
		slog.Warn("prompt: invalid user template, skipping", "name", bp.Name, "err", err)
		return nil
	}

	if len(bp.Schema.Schema) > 0 {
		raw, jerr := json.Marshal(bp.Schema.Schema)
		if jerr != nil {
			if bp.Critical {
				return fmt.Errorf("prompt: invalid schema in %q: %w", bp.Name, jerr)
			}
			slog.Warn("prompt: invalid schema, skipping", "name", bp.Name, "err", jerr)
			return nil
		}
		bp.schemaJSON = raw
		bp.schemaName = bp.Schema.Name
		if bp.schemaName == "" {
			bp.schemaName = bp.Name
		}
	}

	m.blueprints[bp.Name] = bp
	slog.Debug("prompt: loaded blueprint", "name", bp.Name, "version", bp.Version)
	return nil
}

func isYAML(path string) bool {
	return strings.HasSuffix(path, ".yaml") || strings.HasSuffix(path, ".yml")
}

func render(tmpl *template.Template, data any) (string, error) {
	if tmpl == nil {
		return "", nil
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", err
	}
	return buf.String(), nil
}
