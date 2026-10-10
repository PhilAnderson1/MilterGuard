// Package harness deliberately imports no HTML or CSS dependencies.
package harness

import (
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"runtime/debug"
	"strings"
	"syscall"
	"time"
)

type Result struct {
	ViewingCases             int   `json:"viewing_cases"`
	ConditionalFallback      bool  `json:"conditional_fallback"`
	ExpressionWork           int64 `json:"expression_work"`
	ClientDependentTextNodes int   `json:"client_dependent_text_nodes"`
	ConcealedTextNodes       int   `json:"concealed_text_nodes"`
	UnknownTextNodes         int   `json:"unknown_text_nodes"`

	ColourKnownTextNodes     int      `json:"colour_known_text_nodes"`
	ColourUnknownTextNodes   int      `json:"colour_unknown_text_nodes"`
	ColourConcealedTextNodes int      `json:"colour_concealed_text_nodes"`
	Rules                    int      `json:"rules"`
	Selectors                int      `json:"selectors"`
	Uncertainties            int      `json:"uncertainties"`
	MatchWork                int64    `json:"selector_match_work"`
	Warnings                 []string `json:"warnings"`
	Nodes                    int      `json:"nodes"`
	Elements                 int      `json:"elements"`
	TextNodes                int      `json:"text_nodes"`
	TextBytes                int      `json:"text_bytes"`
	BodyTextNodes            int      `json:"body_text_nodes"`
	Checksum                 string   `json:"checksum"`
	Blocked                  int      `json:"blocked_requests"`
	Missing                  []string `json:"missing_or_unsupported_properties"`
	Inspection               any      `json:"-"`
}
type Processor interface {
	Process([]byte, string, bool) (Result, error)
}
type Factory func() (Processor, error)

func usage() (syscall.Rusage, error) {
	var r syscall.Rusage
	e := syscall.Getrusage(syscall.RUSAGE_SELF, &r)
	return r, e
}
func seconds(t syscall.Timeval) float64 { return float64(t.Sec) + float64(t.Usec)/1e6 }
func Main(name string, factory Factory) { os.Exit(Run(name, factory)) }
func Run(name string, factory Factory) int {
	start := time.Now()
	input := flag.String("input", "", "local HTML file (required)")
	mode := flag.String("mode", "styles", "parse or styles")
	iterations := flag.Int("iterations", 100, "fresh documents")
	warmup := flag.Int("warmup", 3, "untimed fresh documents")
	inspect := flag.String("inspect", "", "optional JSON inspection path, separate pass")
	maxInput := flag.Int("max-input-bytes", 8<<20, "input size limit")
	flag.Parse()
	report := map[string]any{"application": name, "input": *input, "mode": *mode, "iterations": *iterations, "warmup": *warmup, "errors": []string{}, "os": runtime.GOOS, "arch": runtime.GOARCH, "go_version": runtime.Version(), "gomaxprocs": runtime.GOMAXPROCS(0)}
	configuration := map[string]string{}
	flag.VisitAll(func(f *flag.Flag) { configuration[f.Name] = f.Value.String() })
	report["configuration"] = configuration
	emit := func(err error) int {
		report["limit_hit"] = err != nil && strings.Contains(err.Error(), "limit:")
		code := 0
		if err != nil {
			report["errors"] = []string{err.Error()}
			code = 1
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
		report["application_wall_seconds_before_report"] = time.Since(start).Seconds()
		e := json.NewEncoder(os.Stdout)
		e.SetIndent("", "  ")
		if e.Encode(report) != nil {
			return 1
		}
		return code
	}
	if *input == "" || (*mode != "parse" && *mode != "styles") || *iterations < 1 || *warmup < 0 || *maxInput < 1 || flag.NArg() != 0 {
		return emit(fmt.Errorf("require --input, --mode=parse|styles, iterations >= 1, warmup >= 0, no positional arguments"))
	}
	for _, k := range []string{"GOGC", "GOMEMLIMIT"} {
		v, ok := os.LookupEnv(k)
		if !ok {
			if k == "GOGC" {
				v = "100 (default)"
			} else {
				v = "unlimited (default)"
			}
		}
		report[strings.ToLower(k)] = v
	}
	if b, e := os.ReadFile("/proc/cpuinfo"); e == nil {
		for _, l := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(l, "model name") {
				report["cpu_model"] = strings.TrimSpace(strings.SplitN(l, ":", 2)[1])
				break
			}
		}
	}
	mods := []map[string]string{}
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, m := range bi.Deps {
			mods = append(mods, map[string]string{"path": m.Path, "version": m.Version, "sum": m.Sum})
		}
		report["build_settings"] = bi.Settings
	}
	report["modules"] = mods
	file, err := os.Open(*input)
	if err != nil {
		return emit(err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, int64(*maxInput)+1))
	if len(data) > *maxInput {
		return emit(fmt.Errorf("limit: input bytes > %d", *maxInput))
	}
	if err != nil {
		return emit(err)
	}
	report["input_bytes"] = len(data)
	report["input_sha256"] = fmt.Sprintf("%x", sha256.Sum256(data))
	t := time.Now()
	processor, err := factory()
	report["initialization_wall_seconds"] = time.Since(t).Seconds()
	if err != nil {
		return emit(err)
	}
	var last Result
	t = time.Now()
	for i := 0; i < *warmup; i++ {
		last, err = processor.Process(data, *mode, false)
		if err != nil {
			return emit(fmt.Errorf("warmup %d: %w", i, err))
		}
	}
	report["warmup_wall_seconds"] = time.Since(t).Seconds()
	last = Result{}
	runtime.GC()
	var before, after, retained runtime.MemStats
	runtime.ReadMemStats(&before)
	ru0, err := usage()
	if err != nil {
		return emit(err)
	}
	completed := 0
	blocked := 0
	t = time.Now()
	for i := 0; i < *iterations; i++ {
		var next Result
		next, err = processor.Process(data, *mode, false)
		if err != nil {
			break
		}
		if i > 0 && (last.Checksum != next.Checksum || last.Nodes != next.Nodes) {
			err = fmt.Errorf("nondeterministic document result")
			break
		}
		last = next
		blocked += next.Blocked
		completed++
	}
	wall := time.Since(t).Seconds()
	ru1, rerr := usage()
	runtime.ReadMemStats(&after)
	runtime.GC()
	runtime.ReadMemStats(&retained)
	report["completed_iterations"] = completed
	report["result_per_document"] = last
	report["blocked_requests_measured_total"] = blocked
	if err != nil {
		return emit(fmt.Errorf("measured iteration %d: %w", completed, err))
	}
	if rerr != nil {
		return emit(rerr)
	}
	n := float64(*iterations)
	u := seconds(ru1.Utime) - seconds(ru0.Utime)
	s := seconds(ru1.Stime) - seconds(ru0.Stime)
	report["measurement"] = map[string]any{"wall_seconds_total": wall, "wall_seconds_per_document": wall / n, "cpu_user_seconds_total": u, "cpu_system_seconds_total": s, "cpu_seconds_per_document": (u + s) / n, "cpu_utilisation_percent": 100 * (u + s) / wall, "allocated_bytes_total": after.TotalAlloc - before.TotalAlloc, "allocated_bytes_per_document": float64(after.TotalAlloc-before.TotalAlloc) / n, "mallocs_total": after.Mallocs - before.Mallocs, "mallocs_per_document": float64(after.Mallocs-before.Mallocs) / n, "heap_before_bytes": before.HeapAlloc, "heap_after_bytes": after.HeapAlloc, "heap_retained_after_gc_bytes": retained.HeapAlloc, "natural_gc_count": after.NumGC - before.NumGC, "natural_gc_pause_ns": after.PauseTotalNs - before.PauseTotalNs, "peak_rss_bytes": ru1.Maxrss * 1024}
	report["peak_rss_scope"] = "whole process through measured loop, includes package initialization, setup and warmup; inspection excluded"
	for _, warning := range last.Warnings {
		fmt.Fprintln(os.Stderr, warning)
	}
	if *inspect != "" {
		res, e := processor.Process(data, *mode, true)
		if e != nil {
			return emit(fmt.Errorf("inspection: %w", e))
		}
		if res.Inspection == nil {
			return emit(fmt.Errorf("inspection unavailable in this mode"))
		}
		b, e := json.MarshalIndent(res.Inspection, "", "  ")
		if e == nil {
			e = os.WriteFile(*inspect, append(b, '\n'), 0644)
		}
		if e != nil {
			return emit(e)
		}
	}
	return emit(nil)
}
