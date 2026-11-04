// Package thinking loads and applies the configurable AI thinking controls.
package thinking

import (
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

const maxCatalogueBytes = 4 << 20
const maxCatalogueDepth = 64
const maxCatalogueNodes = 100_000

type Mode string

const (
	ModeOff    Mode = "off"
	ModeOn     Mode = "on"
	ModeEffort Mode = "effort"
	ModeBudget Mode = "budget"
)

type endpointFile struct {
	SchemaVersion int                           `yaml:"schema_version"`
	Endpoints     map[string]EndpointDefinition `yaml:"endpoints"`
}

type profileFile struct {
	SchemaVersion int                          `yaml:"schema_version"`
	Profiles      map[string]ProfileDefinition `yaml:"profiles"`
}

type EndpointDefinition struct {
	Protocol         string             `yaml:"protocol" json:"protocol"`
	Path             string             `yaml:"path" json:"path"`
	Requests         map[string]any     `yaml:"requests" json:"requests"`
	EffortValues     *[]string          `yaml:"effort_values" json:"effort_values,omitempty"`
	BudgetMin        *int64             `yaml:"budget_min" json:"budget_min,omitempty"`
	BudgetMax        *int64             `yaml:"budget_max" json:"budget_max,omitempty"`
	TemplateDefaults map[string]*string `yaml:"template_defaults" json:"template_defaults,omitempty"`
	SchemaVersion    int                `yaml:"-" json:"schema_version"`
}

type ProfileDefinition struct {
	TemplateParameters map[string]*string `yaml:"template_parameters" json:"template_parameters,omitempty"`
	Options            []OptionDefinition `yaml:"options" json:"options"`
	SchemaVersion      int                `yaml:"-" json:"schema_version"`
}

type OptionDefinition struct {
	ID           string  `yaml:"id" json:"id"`
	Label        string  `yaml:"label" json:"label"`
	Mode         Mode    `yaml:"mode" json:"mode"`
	Effort       *string `yaml:"effort" json:"effort,omitempty"`
	BudgetTokens *int64  `yaml:"budget_tokens" json:"budget_tokens,omitempty"`
	effortSet    bool
	budgetSet    bool
}

type Catalogues struct {
	Endpoints map[string]EndpointDefinition
	Profiles  map[string]ProfileDefinition
}

func (endpoint *EndpointDefinition) UnmarshalYAML(node *yaml.Node) error {
	if err := validateStructuralMapping(node, map[string]bool{
		"protocol": true, "path": true, "requests": true, "effort_values": true,
		"budget_min": true, "budget_max": true, "template_defaults": true,
	}, map[string]bool{
		"effort_values": true, "budget_min": true, "budget_max": true, "template_defaults": true,
	}); err != nil {
		return err
	}
	type plain EndpointDefinition
	var decoded plain
	if err := node.Decode(&decoded); err != nil {
		return err
	}
	*endpoint = EndpointDefinition(decoded)
	return nil
}

func (profile *ProfileDefinition) UnmarshalYAML(node *yaml.Node) error {
	if err := validateStructuralMapping(node,
		map[string]bool{"template_parameters": true, "options": true},
		map[string]bool{"template_parameters": true, "options": true}); err != nil {
		return err
	}
	type plain ProfileDefinition
	var decoded plain
	if err := node.Decode(&decoded); err != nil {
		return err
	}
	*profile = ProfileDefinition(decoded)
	return nil
}

func (option *OptionDefinition) UnmarshalYAML(node *yaml.Node) error {
	if err := validateStructuralMapping(node,
		map[string]bool{"id": true, "label": true, "mode": true, "effort": true, "budget_tokens": true}, nil); err != nil {
		return err
	}
	type plain OptionDefinition
	var decoded plain
	if err := node.Decode(&decoded); err != nil {
		return err
	}
	*option = OptionDefinition(decoded)
	for index := 0; index < len(node.Content); index += 2 {
		switch node.Content[index].Value {
		case "effort":
			option.effortSet = true
		case "budget_tokens":
			option.budgetSet = true
		}
	}
	return nil
}

func validateStructuralMapping(node *yaml.Node, allowed, nonNull map[string]bool) error {
	if node.Kind != yaml.MappingNode {
		return fmt.Errorf("line %d: expected a mapping", node.Line)
	}
	for index := 0; index < len(node.Content); index += 2 {
		key, value := node.Content[index], node.Content[index+1]
		if !allowed[key.Value] {
			return fmt.Errorf("line %d: field %s not found", key.Line, key.Value)
		}
		if nonNull[key.Value] && value.Tag == "!!null" {
			return fmt.Errorf("line %d: field %s must not be null", value.Line, key.Value)
		}
	}
	return nil
}

// LoadCatalogues reads and strictly validates both operator-editable files.
func LoadCatalogues(endpointsPath, profilesPath string) (Catalogues, error) {
	if strings.TrimSpace(endpointsPath) == "" {
		return Catalogues{}, errors.New("ai.endpoints_file is required")
	}
	if strings.TrimSpace(profilesPath) == "" {
		return Catalogues{}, errors.New("ai.profiles_file is required")
	}
	var endpoints endpointFile
	if err := loadYAMLFile(endpointsPath, &endpoints); err != nil {
		return Catalogues{}, fmt.Errorf("load AI endpoint catalogue %s: %w", endpointsPath, err)
	}
	if err := validateEndpointFile(endpointsPath, &endpoints); err != nil {
		return Catalogues{}, err
	}
	var profiles profileFile
	if err := loadYAMLFile(profilesPath, &profiles); err != nil {
		return Catalogues{}, fmt.Errorf("load AI thinking-profile catalogue %s: %w", profilesPath, err)
	}
	if err := validateProfileFile(profilesPath, &profiles); err != nil {
		return Catalogues{}, err
	}
	return Catalogues{Endpoints: endpoints.Endpoints, Profiles: profiles.Profiles}, nil
}

func loadYAMLFile(path string, target any) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxCatalogueBytes+1))
	if err != nil {
		return err
	}
	if len(b) > maxCatalogueBytes {
		return fmt.Errorf("file exceeds %d-byte limit", maxCatalogueBytes)
	}
	var document yaml.Node
	dec := yaml.NewDecoder(strings.NewReader(string(b)))
	if err := dec.Decode(&document); err != nil {
		if errors.Is(err, io.EOF) {
			return errors.New("file is empty")
		}
		return err
	}
	if err := validateYAMLTree(&document); err != nil {
		return err
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); err == nil {
		return errors.New("catalogue must contain exactly one YAML document")
	} else if !errors.Is(err, io.EOF) {
		return fmt.Errorf("invalid trailing YAML: %w", err)
	}
	strict := yaml.NewDecoder(strings.NewReader(string(b)))
	strict.KnownFields(true)
	if err := strict.Decode(target); err != nil {
		return err
	}
	return nil
}

func validateYAMLTree(root *yaml.Node) error {
	nodes := 0
	var walk func(*yaml.Node, int) error
	walk = func(node *yaml.Node, depth int) error {
		if depth > maxCatalogueDepth {
			return fmt.Errorf("YAML nesting exceeds %d levels", maxCatalogueDepth)
		}
		nodes++
		if nodes > maxCatalogueNodes {
			return fmt.Errorf("YAML structure exceeds %d nodes", maxCatalogueNodes)
		}
		if node.Kind == yaml.AliasNode {
			return fmt.Errorf("YAML aliases are not supported at line %d", node.Line)
		}
		switch node.Kind {
		case yaml.MappingNode:
			if node.Tag != "!!map" {
				return fmt.Errorf("unsupported YAML tag %q at line %d", node.Tag, node.Line)
			}
		case yaml.SequenceNode:
			if node.Tag != "!!seq" {
				return fmt.Errorf("unsupported YAML tag %q at line %d", node.Tag, node.Line)
			}
		case yaml.ScalarNode:
			switch node.Tag {
			case "!!str", "!!int", "!!bool", "!!null", "!!float":
			default:
				return fmt.Errorf("unsupported YAML tag %q at line %d", node.Tag, node.Line)
			}
		}
		if node.Kind == yaml.MappingNode {
			seen := make(map[string]bool, len(node.Content)/2)
			for index := 0; index < len(node.Content); index += 2 {
				key := node.Content[index]
				if key.Kind != yaml.ScalarNode || key.Tag != "!!str" {
					return fmt.Errorf("object key at line %d must be a string", key.Line)
				}
				if key.Value == "<<" {
					return fmt.Errorf("YAML merge keys are not supported at line %d", key.Line)
				}
				if seen[key.Value] {
					return fmt.Errorf("duplicate key %q at line %d", key.Value, key.Line)
				}
				seen[key.Value] = true
			}
		}
		for _, child := range node.Content {
			if err := walk(child, depth+1); err != nil {
				return err
			}
		}
		return nil
	}
	return walk(root, 0)
}

func validateEndpointFile(path string, file *endpointFile) error {
	if file.SchemaVersion != 1 && file.SchemaVersion != 2 {
		return fmt.Errorf("%s: schema_version must be 1 or 2", path)
	}
	if file.Endpoints == nil {
		return fmt.Errorf("%s: endpoints mapping is required", path)
	}
	for id, endpoint := range file.Endpoints {
		field := path + ": endpoint " + fmt.Sprintf("%q", id)
		if strings.TrimSpace(id) == "" {
			return fmt.Errorf("%s: endpoint ID must not be empty", path)
		}
		endpoint.SchemaVersion = file.SchemaVersion
		if endpoint.Protocol == "" {
			return fmt.Errorf("%s.protocol is required", field)
		}
		switch endpoint.Protocol {
		case "openai_chat", "ollama_chat", "lm_studio_chat":
		default:
			return fmt.Errorf("%s.protocol %q is unsupported by the catalogue schema", field, endpoint.Protocol)
		}
		if err := validateRoute(endpoint.Path); err != nil {
			return fmt.Errorf("%s.path: %w", field, err)
		}
		if endpoint.Requests == nil {
			return fmt.Errorf("%s.requests is required", field)
		}
		if file.SchemaVersion == 1 && endpoint.TemplateDefaults != nil {
			return fmt.Errorf("%s.template_defaults requires schema version 2", field)
		}
		if err := validateParameters(endpoint.TemplateDefaults, field+".template_defaults"); err != nil {
			return err
		}
		for modeName, raw := range endpoint.Requests {
			mode := Mode(modeName)
			if !validMode(mode) {
				return fmt.Errorf("%s.requests contains unknown mode %q", field, modeName)
			}
			normalized, err := normalizeJSON(raw)
			if err != nil {
				return fmt.Errorf("%s.requests.%s: %w", field, modeName, err)
			}
			fragment, ok := normalized.(map[string]any)
			if !ok {
				return fmt.Errorf("%s.requests.%s must be an object", field, modeName)
			}
			if err := validateFragment(fragment, mode, file.SchemaVersion, field+".requests."+modeName); err != nil {
				return err
			}
			endpoint.Requests[modeName] = fragment
		}
		if endpoint.EffortValues != nil {
			seen := make(map[string]bool, len(*endpoint.EffortValues))
			for _, effort := range *endpoint.EffortValues {
				if effort == "" || seen[effort] {
					return fmt.Errorf("%s.effort_values must contain distinct nonempty strings", field)
				}
				seen[effort] = true
			}
		}
		minimum := int64(1)
		if endpoint.BudgetMin != nil {
			minimum = *endpoint.BudgetMin
		}
		if minimum < 1 {
			return fmt.Errorf("%s.budget_min must be positive", field)
		}
		if endpoint.BudgetMax != nil && (*endpoint.BudgetMax < minimum || *endpoint.BudgetMax < 1) {
			return fmt.Errorf("%s.budget_max must be positive and at least budget_min", field)
		}
		file.Endpoints[id] = endpoint
	}
	return nil
}

func validateProfileFile(path string, file *profileFile) error {
	if file.SchemaVersion != 1 && file.SchemaVersion != 2 {
		return fmt.Errorf("%s: schema_version must be 1 or 2", path)
	}
	if file.Profiles == nil {
		return fmt.Errorf("%s: profiles mapping is required", path)
	}
	for id, profile := range file.Profiles {
		field := path + ": profile " + fmt.Sprintf("%q", id)
		if strings.TrimSpace(id) == "" {
			return fmt.Errorf("%s: profile ID must not be empty", path)
		}
		profile.SchemaVersion = file.SchemaVersion
		if profile.Options == nil {
			return fmt.Errorf("%s.options is required", field)
		}
		if file.SchemaVersion == 1 && profile.TemplateParameters != nil {
			return fmt.Errorf("%s.template_parameters requires schema version 2", field)
		}
		if err := validateParameters(profile.TemplateParameters, field+".template_parameters"); err != nil {
			return err
		}
		seen := make(map[string]bool, len(profile.Options))
		for index, option := range profile.Options {
			optionField := fmt.Sprintf("%s.options[%d]", field, index)
			if option.ID == "" || option.ID == "default" {
				return fmt.Errorf("%s.id must be nonempty and must not be reserved value default", optionField)
			}
			if seen[option.ID] {
				return fmt.Errorf("%s has duplicate option ID %q", field, option.ID)
			}
			seen[option.ID] = true
			if option.Label == "" || !validMode(option.Mode) {
				return fmt.Errorf("%s requires a nonempty label and valid mode", optionField)
			}
			switch option.Mode {
			case ModeEffort:
				if !option.effortSet || option.Effort == nil || *option.Effort == "" || option.budgetSet {
					return fmt.Errorf("%s effort mode requires only a nonempty effort", optionField)
				}
			case ModeBudget:
				if !option.budgetSet || option.BudgetTokens == nil || *option.BudgetTokens < 1 || option.effortSet {
					return fmt.Errorf("%s budget mode requires only a positive budget_tokens", optionField)
				}
			default:
				if option.effortSet || option.budgetSet {
					return fmt.Errorf("%s mode %q forbids effort and budget_tokens", optionField, option.Mode)
				}
			}
		}
		file.Profiles[id] = profile
	}
	return nil
}

var parameterName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func validateParameters(parameters map[string]*string, field string) error {
	for name, value := range parameters {
		if name != "thinking_toggle" {
			return fmt.Errorf("%s contains unknown parameter %q", field, name)
		}
		if value != nil && !parameterName.MatchString(*value) {
			return fmt.Errorf("%s.%s must be null or a JSON property name", field, name)
		}
	}
	return nil
}

func validMode(mode Mode) bool {
	return mode == ModeOff || mode == ModeOn || mode == ModeEffort || mode == ModeBudget
}

func normalizeJSON(value any) (any, error) {
	switch value := value.(type) {
	case nil, string, bool, int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		return value, nil
	case float32:
		if math.IsNaN(float64(value)) || math.IsInf(float64(value), 0) {
			return nil, errors.New("non-finite number is not valid JSON")
		}
		return value, nil
	case float64:
		if math.IsNaN(value) || math.IsInf(value, 0) {
			return nil, errors.New("non-finite number is not valid JSON")
		}
		return value, nil
	case []any:
		result := make([]any, len(value))
		for index, item := range value {
			normalized, err := normalizeJSON(item)
			if err != nil {
				return nil, err
			}
			result[index] = normalized
		}
		return result, nil
	case map[string]any:
		result := make(map[string]any, len(value))
		for key, item := range value {
			normalized, err := normalizeJSON(item)
			if err != nil {
				return nil, err
			}
			result[key] = normalized
		}
		return result, nil
	case map[any]any:
		result := make(map[string]any, len(value))
		for rawKey, item := range value {
			key, ok := rawKey.(string)
			if !ok {
				return nil, errors.New("object key must be a string")
			}
			normalized, err := normalizeJSON(item)
			if err != nil {
				return nil, err
			}
			result[key] = normalized
		}
		return result, nil
	default:
		return nil, fmt.Errorf("value of type %T is not JSON-compatible", value)
	}
}

func validateFragment(fragment map[string]any, mode Mode, schemaVersion int, field string) error {
	var walk func(any, string) error
	walk = func(value any, path string) error {
		switch value := value.(type) {
		case map[string]any:
			for key, child := range value {
				childPath := path + "." + key
				switch {
				case key == "$template.thinking_toggle":
					if schemaVersion < 2 {
						return fmt.Errorf("%s requires schema version 2", childPath)
					}
					if _, ok := child.(bool); !ok {
						return fmt.Errorf("%s value must be a boolean", childPath)
					}
				case key == "$effort" || key == "$budget_tokens":
					return fmt.Errorf("%s: value placeholders cannot be object keys", childPath)
				case strings.HasPrefix(key, "$") || containsReservedToken(key):
					return fmt.Errorf("%s contains an unsupported placeholder", childPath)
				}
				if err := walk(child, childPath); err != nil {
					return err
				}
			}
		case []any:
			for index, child := range value {
				if err := walk(child, fmt.Sprintf("%s[%d]", path, index)); err != nil {
					return err
				}
			}
		case string:
			switch value {
			case "$effort":
				if mode != ModeEffort {
					return fmt.Errorf("%s: $effort is only valid in an effort request", path)
				}
			case "$budget_tokens":
				if mode != ModeBudget {
					return fmt.Errorf("%s: $budget_tokens is only valid in a budget request", path)
				}
			case "$template.thinking_toggle":
				return fmt.Errorf("%s: template placeholders are only valid as object keys", path)
			default:
				if strings.HasPrefix(value, "$") || containsReservedToken(value) {
					return fmt.Errorf("%s contains an unsupported placeholder", path)
				}
			}
		}
		return nil
	}
	return walk(fragment, field)
}

func containsReservedToken(value string) bool {
	return strings.Contains(value, "$template.thinking_toggle") || strings.Contains(value, "$effort") || strings.Contains(value, "$budget_tokens")
}
