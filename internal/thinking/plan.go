package thinking

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
)

type Exclusion struct {
	OptionID string
	Reason   string
}

type Choice struct {
	Index        int
	ID           string
	Label        string
	Mode         Mode
	Effort       string
	BudgetTokens int64
	fragment     map[string]any
}

type Plan struct {
	endpointID         string
	profileID          string
	protocol           string
	route              string
	ladder             []Choice
	exclusions         []Exclusion
	sourceOptionsEmpty bool
	fingerprint        string
}

type Resolution struct {
	Status         string
	RequestedLevel int64
	EffectiveLevel *int
	MaxLevel       *int
	OptionID       string
	Label          string
	Mode           Mode
	Effort         string
	BudgetTokens   int64
	OffAvailable   bool
	Fingerprint    string
	Fragment       map[string]any
}

const (
	MinimumLevel int64 = 0
	MaximumLevel int64 = 4
)

func CompilePlan(catalogues Catalogues, endpointID, profileID string, supportedProtocols map[string]bool) (*Plan, error) {
	endpoint, ok := catalogues.Endpoints[endpointID]
	if !ok {
		return nil, fmt.Errorf("unknown ai.endpoint_type %q", endpointID)
	}
	profile, ok := catalogues.Profiles[profileID]
	if !ok {
		return nil, fmt.Errorf("unknown ai.thinking_profile %q", profileID)
	}
	if !supportedProtocols[endpoint.Protocol] {
		return nil, fmt.Errorf("ai.endpoint_type %q requires unsupported protocol adapter %q", endpointID, endpoint.Protocol)
	}
	offCount := 0
	for _, option := range profile.Options {
		if option.Mode == ModeOff {
			offCount++
		}
	}
	if offCount > 1 {
		return nil, fmt.Errorf("thinking profile %q has ambiguous_level_order: multiple Off options", profileID)
	}
	plan := &Plan{
		endpointID: endpointID, profileID: profileID, protocol: endpoint.Protocol,
		route: endpoint.Path, sourceOptionsEmpty: len(profile.Options) == 0,
	}
	choices := make([]Choice, 0, len(profile.Options))
	for _, option := range profile.Options {
		raw, exists := endpoint.Requests[string(option.Mode)]
		if !exists {
			plan.exclusions = append(plan.exclusions, Exclusion{OptionID: option.ID, Reason: "endpoint does not support mode " + string(option.Mode)})
			continue
		}
		if option.Mode == ModeEffort && endpoint.EffortValues != nil && !containsString(*endpoint.EffortValues, *option.Effort) {
			plan.exclusions = append(plan.exclusions, Exclusion{OptionID: option.ID, Reason: "effort is not allowed by endpoint"})
			continue
		}
		if option.Mode == ModeBudget {
			minimum := int64(1)
			if endpoint.BudgetMin != nil {
				minimum = *endpoint.BudgetMin
			}
			if *option.BudgetTokens < minimum || endpoint.BudgetMax != nil && *option.BudgetTokens > *endpoint.BudgetMax {
				plan.exclusions = append(plan.exclusions, Exclusion{OptionID: option.ID, Reason: "budget is outside endpoint range"})
				continue
			}
		}
		fragment, err := renderFragment(raw.(map[string]any), option, endpoint.TemplateDefaults, profile.TemplateParameters)
		if err != nil {
			return nil, fmt.Errorf("endpoint %q profile %q option %q: %w", endpointID, profileID, option.ID, err)
		}
		if len(fragment) == 0 {
			plan.exclusions = append(plan.exclusions, Exclusion{OptionID: option.ID, Reason: "rendered request fragment is empty"})
			continue
		}
		choice := Choice{ID: option.ID, Label: option.Label, Mode: option.Mode, fragment: fragment}
		if option.Effort != nil {
			choice.Effort = *option.Effort
		}
		if option.BudgetTokens != nil {
			choice.BudgetTokens = *option.BudgetTokens
		}
		choices = append(choices, choice)
	}
	if !plan.sourceOptionsEmpty && len(choices) == 0 {
		return nil, fmt.Errorf("endpoint %q and profile %q have no_usable_thinking_options", endpointID, profileID)
	}
	// Off is always numerical level zero; other choices retain profile order.
	for _, choice := range choices {
		if choice.Mode == ModeOff {
			plan.ladder = append(plan.ladder, choice)
			break
		}
	}
	for _, choice := range choices {
		if choice.Mode != ModeOff {
			plan.ladder = append(plan.ladder, choice)
		}
	}
	for index := range plan.ladder {
		plan.ladder[index].Index = index
	}
	fingerprintSource := struct {
		EndpointID string
		ProfileID  string
		Endpoint   EndpointDefinition
		Profile    ProfileDefinition
		Algorithm  int
	}{endpointID, profileID, endpoint, profile, 2}
	encoded, err := json.Marshal(fingerprintSource)
	if err != nil {
		return nil, fmt.Errorf("fingerprint thinking plan: %w", err)
	}
	sum := sha256.Sum256(encoded)
	plan.fingerprint = hex.EncodeToString(sum[:])
	return plan, nil
}

func (p *Plan) EndpointID() string {
	return p.endpointID
}

func (p *Plan) ProfileID() string {
	return p.profileID
}

func (p *Plan) Protocol() string {
	return p.protocol
}

func (p *Plan) Route() string {
	return p.route
}
func (p *Plan) Exclusions() []Exclusion {
	return append([]Exclusion(nil), p.exclusions...)
}

func (p *Plan) ResolveLevel(level int64) (Resolution, error) {
	if level < MinimumLevel || level > MaximumLevel {
		return Resolution{}, fmt.Errorf("thinking level must be between %d and %d", MinimumLevel, MaximumLevel)
	}
	result := Resolution{
		RequestedLevel: level, Fingerprint: p.fingerprint,
		OffAvailable: len(p.ladder) > 0 && p.ladder[0].Mode == ModeOff,
		Fragment:     make(map[string]any),
	}
	if p.sourceOptionsEmpty {
		result.Status = "uncontrolled"
		return result, nil
	}
	index := p.normalizedChoiceIndex(level)
	choice := p.ladder[index]
	result.Status = "selected"
	result.EffectiveLevel = intPointer(int(level))
	result.MaxLevel = intPointer(int(MaximumLevel))
	result.OptionID = choice.ID
	result.Label = choice.Label
	result.Mode = choice.Mode
	result.Effort = choice.Effort
	result.BudgetTokens = choice.BudgetTokens
	result.Fragment = cloneMap(choice.fragment)
	return result, nil
}

// normalizedChoiceIndex maps the user-facing 0-4 preference onto the
// effective choices without requiring callers to know how many choices a
// model exposes. Where Off exists, zero selects it and levels 1-4 span only
// the enabled choices. Otherwise the whole scale spans the available choices.
func (p *Plan) normalizedChoiceIndex(level int64) int {
	if len(p.ladder) == 1 {
		return 0
	}
	if p.ladder[0].Mode == ModeOff {
		if level == MinimumLevel {
			return 0
		}
		return 1 + scaleLevel(level-1, MaximumLevel-1, len(p.ladder)-2)
	}
	return scaleLevel(level, MaximumLevel, len(p.ladder)-1)
}

// scaleLevel selects the nearest point on a zero-based target scale while
// preserving both endpoints exactly.
func scaleLevel(value, sourceMaximum int64, targetMaximum int) int {
	if targetMaximum == 0 {
		return 0
	}
	return int((value*int64(targetMaximum) + sourceMaximum/2) / sourceMaximum)
}

func (p *Plan) ValidateBaseRequest(base map[string]any) error {
	for _, choice := range p.ladder {
		if _, err := Merge(base, choice.fragment); err != nil {
			return fmt.Errorf("thinking option %q conflicts with ordinary AI request: %w", choice.ID, err)
		}
	}
	return nil
}

func ApplyResolution(base map[string]any, resolution Resolution) (map[string]any, error) {
	if resolution.Status == "uncontrolled" || len(resolution.Fragment) == 0 {
		return cloneMap(base), nil
	}
	return Merge(base, resolution.Fragment)
}

func Merge(base, fragment map[string]any) (map[string]any, error) {
	result := cloneMap(base)
	if err := mergeObject(result, fragment, "$"); err != nil {
		return nil, err
	}
	return result, nil
}

func mergeObject(destination, fragment map[string]any, path string) error {
	for key, incoming := range fragment {
		current, exists := destination[key]
		if !exists {
			destination[key] = cloneValue(incoming)
			continue
		}
		currentObject, currentOK := current.(map[string]any)
		incomingObject, incomingOK := incoming.(map[string]any)
		if !currentOK || !incomingOK {
			return fmt.Errorf("request field conflict at %s.%s", path, key)
		}
		if err := mergeObject(currentObject, incomingObject, path+"."+key); err != nil {
			return err
		}
	}
	return nil
}

func ResolveEndpointURL(base, route string) (string, error) {
	parsed, err := url.Parse(base)
	if err != nil || !parsed.IsAbs() || parsed.Host == "" || parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", errors.New("ai.endpoint must be an absolute HTTP(S) base URL")
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", errors.New("ai.endpoint must not contain a query or fragment")
	}
	if parsed.User != nil {
		return "", errors.New("ai.endpoint must not contain credentials")
	}
	return strings.TrimRight(base, "/") + route, nil
}

func validateRoute(route string) error {
	if !strings.HasPrefix(route, "/") || strings.HasPrefix(route, "//") {
		return errors.New("must start with exactly one slash")
	}
	parsed, err := url.Parse(route)
	if err != nil || parsed.IsAbs() || parsed.Host != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return errors.New("must be a route without scheme, authority, query, or fragment")
	}
	for _, segment := range strings.Split(parsed.EscapedPath(), "/") {
		decoded, err := url.PathUnescape(segment)
		if err != nil || decoded == ".." {
			return errors.New("must not contain parent-directory traversal")
		}
	}
	return nil
}

func containsString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func intPointer(value int) *int { return &value }

func cloneMap(value map[string]any) map[string]any {
	result := make(map[string]any, len(value))
	for key, item := range value {
		result[key] = cloneValue(item)
	}
	return result
}

func cloneValue(value any) any {
	switch value := value.(type) {
	case map[string]any:
		return cloneMap(value)
	case []any:
		result := make([]any, len(value))
		for index, item := range value {
			result[index] = cloneValue(item)
		}
		return result
	default:
		return value
	}
}
