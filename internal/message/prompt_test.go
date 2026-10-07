package message

// Prompt is a test convenience for exercising text-only analysis generation.
func (m *Message) Prompt(maxChars int) string {
	return promptWithContext(m, AnalysisContext{}, maxChars)
}

func promptWithContext(m *Message, context AnalysisContext, maxChars int) string {
	return m.BuildAnalysis(context, maxChars, VisionOptions{Mode: "off"}).Prompt
}
