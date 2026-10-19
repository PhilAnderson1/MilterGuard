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
func ParseFloat(m *Memory, text string, bits int) (float64, error) {
	size := int64(len(text))
	if size > (int64(^uint64(0)>>1)-128)/2 {
		m.reject()
		return 0, ErrMemory
	}
	if m.Exhausted() || !m.Reserve(size+size/4+64+int64(unsafe.Sizeof(strconv.NumError{}))+16) {
		return 0, ErrMemory
	}
	return strconv.ParseFloat(text, bits)
}
func ParseMediaType(m *Memory, text string) (string, map[string]string, error) {
	size, ok := storageBytes(len(text), 32)
	if !ok || size > int64(^uint64(0)>>1)-256 {
		m.reject()
		return "", nil, ErrMemory
	}
	if m.Exhausted() || !m.Reserve(256+size) {
		return "", nil, ErrMemory
	}
	return mime.ParseMediaType(text)
}
func RegexpSplit(m *Memory, re *regexp.Regexp, text string, limit int) ([]string, bool) {
	// Extraction uses a bounded positive result limit. Unbounded library calls
	// are deliberately not admitted through this adapter.
	if limit <= 0 {
		return nil, m.reject()
	}
	size, ok := storageBytes(limit, 128)
	if !ok {
		return nil, m.reject()
	}
	if m.Exhausted() || !m.Reserve(size) {
		return nil, false
	}
	return re.Split(text, limit), true
}
func RegexpSubmatch(m *Memory, re *regexp.Regexp, text string) ([]string, bool) {
	size, ok := storageBytes(re.NumSubexp()+1, 64)
	if !ok {
		return nil, m.reject()
	}
	if m.Exhausted() || !m.Reserve(size) {
		return nil, false
	}
	return re.FindStringSubmatch(text), true
}
func DecodeBase64(m *Memory, text string) ([]byte, error) {
	size := base64.StdEncoding.DecodedLen(len(text))
	out, ok := MakeSlice[byte](m, size, size)
	if !ok {
		return nil, ErrMemory
	}
	n, err := base64.StdEncoding.Decode(out, []byte(text))
	return out[:n], err
}
func UnescapePathBytes(m *Memory, text string, stop Stop) ([]byte, error) {
	// PathUnescape returns the original string when unchanged. Only escaping
	// needs a temporary string allowance; the mutable output always has an owner.
	escaped := false
	for i := 0; i < len(text); i++ {
		if i%WorkChunk == 0 && stopped(stop) {
			return nil, ErrStopped
		}
		if text[i] == '%' {
			escaped = true
		}
	}
	if escaped && (m.Exhausted() || !m.Reserve(int64(len(text)))) {
		return nil, ErrMemory
	}
	decoded, err := url.PathUnescape(text)
	if err != nil {
		return nil, err
	}
	out, ok := StringBytes(m, decoded, false, stop)
	if !ok {
		if m.Exhausted() {
			return nil, ErrMemory
		}
		return nil, ErrStopped
	}
	return out, nil
}
