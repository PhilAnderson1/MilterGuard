package thinking

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func currentCatalogues(t *testing.T) Catalogues {
	t.Helper()
	catalogues, err := LoadCatalogues(
		filepath.Join("..", "..", "configs", "endpoints.yaml"),
		filepath.Join("..", "..", "configs", "thinking-profiles.yaml"),
	)
	if err != nil {
		t.Fatal(err)
	}
	return catalogues
}

func currentPlan(t *testing.T, endpoint, profile string) *Plan {
	t.Helper()
	plan, err := CompilePlan(currentCatalogues(t), endpoint, profile, map[string]bool{"openai_chat": true})
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func TestCurrentCatalogueExamples(t *testing.T) {
	tests := []struct {
		endpoint, profile string
		level             int64
		want              string
	}{
		{"gufo", "qwen3_8", 0, `{"chat_template_kwargs":{"enable_thinking":false}}`},
		{"gufo", "qwen3_8", 3, `{"chat_template_kwargs":{"enable_thinking":true},"reasoning_effort":"medium"}`},
		{"gufo", "qwen3_8", 4, `{"chat_template_kwargs":{"enable_thinking":true},"reasoning_effort":"xhigh"}`},
		{"vllm", "kimi_k2_6", 0, `{"chat_template_kwargs":{"thinking":false}}`},
		{"vllm", "kimi_k2_6", 1, `{"chat_template_kwargs":{"thinking":true}}`},
		{"vllm", "kimi_k3", 0, `{"reasoning_effort":"low"}`},
		{"lm_studio", "qwen3_8", 0, `{"reasoning_effort":"none"}`},
		{"openrouter", "qwen3_8", 4, `{"reasoning":{"effort":"xhigh"}}`},
	}
	for _, test := range tests {
		name := test.endpoint + "/" + test.profile
		t.Run(name, func(t *testing.T) {
			resolution, err := currentPlan(t, test.endpoint, test.profile).ResolveLevel(test.level)
			if err != nil {
				t.Fatal(err)
			}
			encoded, err := json.Marshal(resolution.Fragment)
			if err != nil {
				t.Fatal(err)
			}
			if string(encoded) != test.want {
				t.Fatalf("fragment = %s, want %s", encoded, test.want)
			}
		})
	}
}

func TestNormalizedSelectionAndEmptyProfile(t *testing.T) {
	plan := currentPlan(t, "gufo", "qwen3_8")
	for level, want := range []string{"off", "low", "medium", "medium", "high"} {
		resolution, err := plan.ResolveLevel(int64(level))
		if err != nil {
			t.Fatal(err)
		}
		if resolution.OptionID != want || resolution.EffectiveLevel == nil || *resolution.EffectiveLevel != level || resolution.MaxLevel == nil || *resolution.MaxLevel != 4 {
			t.Fatalf("level %d resolved to %+v, want %s", level, resolution, want)
		}
	}
	for level, want := range []string{"low", "medium", "medium", "high", "high"} {
		resolution, err := currentPlan(t, "openrouter", "gpt_oss").ResolveLevel(int64(level))
		if err != nil {
			t.Fatal(err)
		}
		if resolution.OptionID != want {
			t.Fatalf("thinking-only level %d selected %q, want %q", level, resolution.OptionID, want)
		}
	}
	for level, want := range []string{"low", "medium", "high", "xhigh", "max"} {
		resolution, err := currentPlan(t, "openrouter", "minimax_m3_1_flash").ResolveLevel(int64(level))
		if err != nil {
			t.Fatal(err)
		}
		if resolution.OptionID != want {
			t.Fatalf("five-choice level %d selected %q, want %q", level, resolution.OptionID, want)
		}
	}
	for level := int64(1); level <= MaximumLevel; level++ {
		resolution, err := currentPlan(t, "openrouter", "qwen3_6").ResolveLevel(level)
		if err != nil {
			t.Fatal(err)
		}
		if resolution.OptionID != "on" {
			t.Fatalf("toggle level %d selected %q, want on", level, resolution.OptionID)
		}
	}
	empty, err := currentPlan(t, "openrouter", "none").ResolveLevel(4)
	if err != nil {
		t.Fatal(err)
	}
	if empty.Status != "uncontrolled" || empty.EffectiveLevel != nil || empty.MaxLevel != nil || len(empty.Fragment) != 0 {
		t.Fatalf("empty profile resolution = %+v", empty)
	}
	if _, err := plan.ResolveLevel(-1); err == nil {
		t.Fatal("negative thinking level accepted")
	}
	if _, err := plan.ResolveLevel(5); err == nil {
		t.Fatal("thinking level above four accepted")
	}
}

func TestEndpointLimitExcludesChoiceWithoutRenumberingGap(t *testing.T) {
	plan := currentPlan(t, "lm_studio", "qwen3_6")
	resolution, err := plan.ResolveLevel(4)
	if err != nil {
		t.Fatal(err)
	}
	if resolution.OptionID != "off" || len(plan.Exclusions()) != 1 || plan.Exclusions()[0].OptionID != "on" {
		t.Fatalf("limited plan resolution=%+v exclusions=%+v", resolution, plan.Exclusions())
	}
}

func TestConflictAwareMerge(t *testing.T) {
	merged, err := Merge(
		map[string]any{"reasoning": map[string]any{"summary": "brief"}},
		map[string]any{"reasoning": map[string]any{"effort": "high"}},
	)
	if err != nil {
		t.Fatal(err)
	}
	reasoning := merged["reasoning"].(map[string]any)
	if reasoning["summary"] != "brief" || reasoning["effort"] != "high" {
		t.Fatalf("merged request = %#v", merged)
	}
	if _, err := Merge(map[string]any{"reasoning_effort": "low"}, map[string]any{"reasoning_effort": "high"}); err == nil {
		t.Fatal("conflicting leaf was overwritten")
	}
}

func TestStrictCatalogueLoading(t *testing.T) {
	directory := t.TempDir()
	validProfiles := "schema_version: 2\nprofiles:\n  none:\n    options: []\n"
	profiles := filepath.Join(directory, "profiles.yaml")
	if err := os.WriteFile(profiles, []byte(validProfiles), 0600); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name, endpoints, want string
	}{
		{"duplicate", "schema_version: 2\nendpoints:\n  x:\n    protocol: openai_chat\n    protocol: openai_chat\n    path: /chat/completions\n    requests: {}\n", "duplicate"},
		{"unknown field", "schema_version: 2\nendpoints:\n  x:\n    protocol: openai_chat\n    path: /chat/completions\n    requests: {}\n    surprise: true\n", "surprise"},
		{"custom tag", "schema_version: 2\nendpoints: !custom {}\n", "tag"},
		{"null list", "schema_version: 2\nendpoints:\n  x:\n    protocol: openai_chat\n    path: /chat/completions\n    requests: {}\n    effort_values: null\n", "must not be null"},
		{"traversal", "schema_version: 2\nendpoints:\n  x:\n    protocol: openai_chat\n    path: /../chat/completions\n    requests: {}\n", "traversal"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			endpoints := filepath.Join(directory, test.name+".yaml")
			if err := os.WriteFile(endpoints, []byte(test.endpoints), 0600); err != nil {
				t.Fatal(err)
			}
			_, err := LoadCatalogues(endpoints, profiles)
			if err == nil || !strings.Contains(strings.ToLower(err.Error()), test.want) {
				t.Fatalf("error = %v, want text %q", err, test.want)
			}
		})
	}
}

func TestEndpointURLPreservesBasePath(t *testing.T) {
	got, err := ResolveEndpointURL("https://host.example/proxy/v1/", "/chat/completions")
	if err != nil {
		t.Fatal(err)
	}
	if got != "https://host.example/proxy/v1/chat/completions" {
		t.Fatalf("resolved URL = %q", got)
	}
	for _, invalid := range []string{"relative/v1", "https://host/v1?key=value", "https://user:secret@host/v1", "ftp://host/v1"} {
		if _, err := ResolveEndpointURL(invalid, "/chat/completions"); err == nil {
			t.Fatalf("invalid base URL %q accepted", invalid)
		}
	}
}

func TestOffIsMovedFirstAndMaximumNormalizedLevelSelectsHighest(t *testing.T) {
	effort := "low"
	profile := ProfileDefinition{Options: []OptionDefinition{
		{ID: "low", Label: "Low", Mode: ModeEffort, Effort: &effort},
		{ID: "off", Label: "Off", Mode: ModeOff},
	}}
	plan, err := CompilePlan(Catalogues{
		Endpoints: map[string]EndpointDefinition{"endpoint": {
			Protocol: "openai_chat", Path: "/chat/completions",
			Requests: map[string]any{"off": map[string]any{"think": false}, "effort": map[string]any{"effort": "$effort"}},
		}},
		Profiles: map[string]ProfileDefinition{"profile": profile},
	}, "endpoint", "profile", map[string]bool{"openai_chat": true})
	if err != nil {
		t.Fatal(err)
	}
	zero, err := plan.ResolveLevel(0)
	if err != nil || zero.OptionID != "off" {
		t.Fatalf("level zero = %+v, %v", zero, err)
	}
	maximum, err := plan.ResolveLevel(4)
	if err != nil || maximum.OptionID != "low" {
		t.Fatalf("maximum level = %+v, %v", maximum, err)
	}
	if _, err := plan.ResolveLevel(int64(^uint64(0) >> 1)); err == nil {
		t.Fatal("out-of-range level accepted")
	}
	profile.Options = append(profile.Options, OptionDefinition{ID: "other-off", Label: "Other Off", Mode: ModeOff})
	if _, err := CompilePlan(Catalogues{
		Endpoints: map[string]EndpointDefinition{"endpoint": {Protocol: "openai_chat", Path: "/chat/completions", Requests: map[string]any{"off": map[string]any{"think": false}}}},
		Profiles:  map[string]ProfileDefinition{"profile": profile},
	}, "endpoint", "profile", map[string]bool{"openai_chat": true}); err == nil || !strings.Contains(err.Error(), "ambiguous_level_order") {
		t.Fatalf("multiple Off options error = %v", err)
	}
}

func TestNullTemplateParameterPrunesOnlyDynamicContent(t *testing.T) {
	nullParameter := map[string]*string{"thinking_toggle": nil}
	effort := "high"
	fragment := map[string]any{
		"chat_template_kwargs": map[string]any{"$template.thinking_toggle": true},
		"authored_empty":       map[string]any{},
		"items": []any{
			map[string]any{"$template.thinking_toggle": true},
		},
		"reasoning_effort": "$effort",
	}
	rendered, err := renderFragment(fragment, OptionDefinition{Mode: ModeEffort, Effort: &effort}, nil, nullParameter)
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := rendered["chat_template_kwargs"]; exists {
		t.Fatalf("dynamic-only object was not pruned: %#v", rendered)
	}
	if _, exists := rendered["authored_empty"]; !exists {
		t.Fatalf("authored empty object was pruned: %#v", rendered)
	}
	items := rendered["items"].([]any)
	if len(items) != 1 || len(items[0].(map[string]any)) != 0 || rendered["reasoning_effort"] != "high" {
		t.Fatalf("array position or effort substitution changed: %#v", rendered)
	}
}

func TestPlanRejectsUnresolvedTemplateAndUnsupportedSelectedProtocol(t *testing.T) {
	profile := ProfileDefinition{Options: []OptionDefinition{{ID: "off", Label: "Off", Mode: ModeOff}}}
	catalogues := Catalogues{
		Endpoints: map[string]EndpointDefinition{"endpoint": {
			Protocol: "openai_chat", Path: "/chat/completions",
			Requests: map[string]any{"off": map[string]any{"kwargs": map[string]any{"$template.thinking_toggle": false}}},
		}},
		Profiles: map[string]ProfileDefinition{"profile": profile},
	}
	if _, err := CompilePlan(catalogues, "endpoint", "profile", map[string]bool{"openai_chat": true}); err == nil || !strings.Contains(err.Error(), "unresolved") {
		t.Fatalf("unresolved template error = %v", err)
	}
	endpoint := catalogues.Endpoints["endpoint"]
	endpoint.Protocol = "ollama_chat"
	catalogues.Endpoints["endpoint"] = endpoint
	if _, err := CompilePlan(catalogues, "endpoint", "profile", map[string]bool{"openai_chat": true}); err == nil || !strings.Contains(err.Error(), "unsupported protocol") {
		t.Fatalf("unsupported protocol error = %v", err)
	}
}
