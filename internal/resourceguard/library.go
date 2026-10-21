package resourceguard

import (
	"encoding/base64"
	"mime"
	"net/url"
	"regexp"
	"strconv"
	"unsafe"
)

// Library adapters own admission and the allocating call together. These
// conservative allowances cover implementation-dependent temporary work; they
// are not exact allocator layouts. Revalidate them on Go upgrades.
// ParseURL includes the allowance for callers obtaining EscapedPath and
// EscapedFragment: decoding, re-escaping and error strings can copy the input.
func ParseURL(m *Memory, text string) (*url.URL, error) {
	size, ok := storageBytes(len(text), 8)
	if !ok || size > int64(^uint64(0)>>1)-1024 {
		m.reject()
	}

	m.Reserve(size + 1024)

	return url.Parse(text)
}

func ParseFloat(m *Memory, text string, bits int) (float64, error) {
	size := int64(len(text))
	if size > (int64(^uint64(0)>>1)-128)/2 {
		m.reject()
	}

	m.Reserve(size + size/4 + 64 + int64(unsafe.Sizeof(strconv.NumError{})) + 16)

	return strconv.ParseFloat(text, bits)
}
func ParseMediaType(m *Memory, text string) (string, map[string]string, error) {
	size, ok := storageBytes(len(text), 32)
	if !ok || size > int64(^uint64(0)>>1)-256 {
		m.reject()
	}

	m.Reserve(256 + size)

	return mime.ParseMediaType(text)
}
func RegexpSplit(m *Memory, re *regexp.Regexp, text string, limit int) []string {
	// Extraction uses a bounded positive result limit. Unbounded library calls
	// are deliberately not admitted through this adapter.
	if limit <= 0 {
		m.reject()
		return nil
	}
	size, ok := storageBytes(limit, 128)
	if !ok {
		m.reject()
		return nil
	}

	m.Reserve(size)

	return re.Split(text, limit)
}
func RegexpSubmatch(m *Memory, re *regexp.Regexp, text string) []string {
	size, ok := storageBytes(re.NumSubexp()+1, 64)
	if !ok {
		m.reject()
		return nil
	}

	m.Reserve(size)

	return re.FindStringSubmatch(text)
}

func DecodeBase64(m *Memory, text string) ([]byte, error) {
	// Admit the source conversion even when the compiler currently elides its
	// copy. Accounting must not depend on escape-analysis optimizations.
	m.Reserve(int64(len(text)))
	size := base64.StdEncoding.DecodedLen(len(text))
	out := MakeSlice[byte](m, size, size)

	n, err := base64.StdEncoding.Decode(out, []byte(text))
	return out[:n], err
}
func UnescapePathBytes(m *Memory, text string, stop Stop) ([]byte, error) {
	// PathUnescape returns the original string when unchanged. Only escaping
	// needs a temporary string allowance; the mutable output always has an owner.
	escaped := false
	for i := 0; i < len(text); i++ {
		if i > 0 && i%WorkChunk == 0 {
			if stop != nil {
				stop()
			}
		}

		if text[i] == '%' {
			escaped = true
			break
		}
	}

	if escaped {
		m.unavailable()
		m.Reserve(int64(len(text)))
	}

	decoded, err := url.PathUnescape(text)
	if err != nil {
		return nil, err
	}
	out := StringBytes(m, decoded, false, stop)

	return out, nil
}
