package message

// Prompt is a test convenience for exercising text-only analysis generation.
func (m *Message) Prompt(maxChars int) string {
	return m.BuildAnalysis(maxChars, VisionOptions{Mode: "off"}).Prompt
}
