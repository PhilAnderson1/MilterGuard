package message

import (
	"strings"
	"testing"
)

func TestTextOnlyImageExtractionFitsSmallMemoryBudget(t *testing.T) {
	// The decoded image is larger than the extraction allowance. Text-only
	// callers should validate it without reserving a decoded payload buffer.
	m := New(1 << 20)
	m.AddHeader("Content-Type", "image/png; name=large.png")
	m.AddHeader("Content-Transfer-Encoding", "base64")
	m.AddBody([]byte(strings.Repeat("YWFh", 64<<10)))
	memoryCalls := 0
	control := HTMLProcessingControl{MemoryBytes: 64 << 10, StopOnMemoryLimit: true,
		MemoryLimitExceeded: func() { memoryCalls++ },
	}
	analysis := m.BuildAnalysisWithHTMLControl(AnalysisContext{}, 1000, VisionOptions{Mode: "off"}, control)
	if analysis.BodyExtractionIncomplete || memoryCalls != 0 || len(analysis.Images) != 0 {
		t.Fatalf("vision-off extraction failed: %+v", analysis)
	}
	if !strings.Contains(analysis.Prompt, "[attachment: large.png; type=image/png]") {
		t.Fatalf("attachment marker missing: %s", analysis.Prompt)
	}
	for _, mode := range []string{"always", "fallback"} {
		memoryCalls = 0
		withImages := m.BuildAnalysisWithHTMLControl(AnalysisContext{}, 1000, VisionOptions{Mode: mode}, control)
		if memoryCalls != 1 || !withImages.BodyExtractionIncomplete {
			t.Fatalf("%s should still retain and charge decoded image data", mode)
		}
	}
	if body := m.VisibleBodyWithHTMLControl(1000, control); strings.Contains(body, "incomplete") {
		t.Fatalf("visible body unnecessarily exceeded the allowance: %s", body)
	}
	if _, complete := m.CommandTextResult(-1, control); !complete {
		t.Fatal("command extraction unnecessarily exceeded the allowance")
	}
}

func TestDiscardedImagesPreserveTransferDiagnostics(t *testing.T) {
	for _, encoding := range []string{"base64", "quoted-printable", "x-unknown"} {
		for _, data := range []string{"", onePixelPNG, "YQ", "%%%", "=XX"} {
			t.Run(encoding+"/"+data, func(t *testing.T) {
				m := New(1 << 20)
				m.AddHeader("Content-Type", "image/png; name=test.png")
				m.AddHeader("Content-Transfer-Encoding", encoding)
				m.AddBody([]byte(data))
				retained := m.processedContentWithHTMLControl(HTMLProcessingControl{}, true, true)
				discarded := m.processedContentWithHTMLControl(HTMLProcessingControl{}, false, false)
				if discarded.Text != retained.Text || discarded.TransferIncomplete != retained.TransferIncomplete || discarded.incomplete() != retained.incomplete() {
					t.Fatalf("discarding image changed evidence: retained=%+v discarded=%+v", retained, discarded)
				}
				if len(discarded.Images) != 0 {
					t.Fatal("text-only extraction retained image data")
				}
				analysis := m.BuildAnalysisWithHTMLControl(AnalysisContext{}, 1000, VisionOptions{Mode: "off"}, HTMLProcessingControl{})
				if analysis.BodyExtractionIncomplete != retained.incomplete() {
					t.Fatal("vision-off analysis lost transfer diagnostics")
				}
				if _, complete := m.CommandTextResult(-1, HTMLProcessingControl{}); complete == retained.incomplete() {
					t.Fatal("command extraction lost transfer diagnostics")
				}
			})
		}
	}
}

func TestDiscardedNestedImagesPreserveText(t *testing.T) {
	m := imageOnlyMessage("cid:scam-image", "<scam-image>")
	retained := m.processedContentWithHTMLControl(HTMLProcessingControl{}, true, true)
	discarded := m.processedContentWithHTMLControl(HTMLProcessingControl{}, false, false)
	if len(retained.Images) == 0 || len(discarded.Images) != 0 {
		t.Fatalf("nested image counts: retained=%d discarded=%d", len(retained.Images), len(discarded.Images))
	}
	if discarded.Text != retained.Text || discarded.VisibleText != retained.VisibleText || discarded.incomplete() != retained.incomplete() {
		t.Fatalf("discarding nested images changed text or completeness: retained=%+v discarded=%+v", retained, discarded)
	}
}
