package thinking

import "fmt"

func renderFragment(raw map[string]any, option OptionDefinition, endpointParameters, profileParameters map[string]*string) (map[string]any, error) {
	parameter, present := endpointParameters["thinking_toggle"]
	if override, overridden := profileParameters["thinking_toggle"]; overridden {
		parameter, present = override, true
	}
	value, _, err := renderValue(raw, option, parameter, present, false)
	if err != nil {
		return nil, err
	}
	return value.(map[string]any), nil
}

// renderValue returns the rendered value and whether an object became empty
// solely because a dynamic field was omitted. Array elements are never pruned.
func renderValue(value any, option OptionDefinition, parameter *string, parameterPresent, inArray bool) (any, bool, error) {
	switch value := value.(type) {
	case map[string]any:
		result := make(map[string]any, len(value))
		removedDynamic := false
		for originalKey, originalValue := range value {
			key := originalKey
			if originalKey == "$template.thinking_toggle" {
				if !parameterPresent {
					return nil, false, fmt.Errorf("thinking_toggle template parameter is unresolved")
				}
				if parameter == nil {
					removedDynamic = true
					continue
				}
				key = *parameter
			}
			rendered, prune, err := renderValue(originalValue, option, parameter, parameterPresent, false)
			if err != nil {
				return nil, false, err
			}
			if prune {
				removedDynamic = true
				continue
			}
			if _, collision := result[key]; collision {
				return nil, false, fmt.Errorf("rendered request key collision at %q", key)
			}
			result[key] = rendered
		}
		prune := len(value) > 0 && len(result) == 0 && removedDynamic && !inArray
		return result, prune, nil
	case []any:
		result := make([]any, len(value))
		for index, item := range value {
			rendered, _, err := renderValue(item, option, parameter, parameterPresent, true)
			if err != nil {
				return nil, false, err
			}
			result[index] = rendered
		}
		return result, false, nil
	case string:
		switch value {
		case "$effort":
			return *option.Effort, false, nil
		case "$budget_tokens":
			return *option.BudgetTokens, false, nil
		default:
			return value, false, nil
		}
	default:
		return value, false, nil
	}
}
