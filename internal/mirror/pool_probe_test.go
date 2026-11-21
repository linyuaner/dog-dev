package mirror

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/ghpp/ghpp/internal/config"
)

// TestProbeTargetOK 验证探测目标过滤规则。
func TestProbeTargetOK(t *testing.T) {
	pathfetch := config.Mirror{ID: "xget", Kind: config.KindPathFetch, URL: "https://xget.example/gh", Enabled: true}
	prefix := config.Mirror{ID: "pref", Kind: config.KindPrefix, URL: "https://ghproxy.example", Enabled: true}

	codeload := config.ProbeTarget{Host: "codeload.github.com", Path: "/o/r/tar.gz/main", Category: config.CatRaw}
	raw := config.ProbeTarget{Host: "raw.githubusercontent.com", Path: "/o/r/main/f", Category: config.CatRaw}

	// pathfetch：codeload 上游行为不稳定 → 不探测；raw 实测可用 → 探测。
	if ProbeTargetOK(pathfetch, codeload) {
		t.Fatalf("pathfetch 不应探测 codeload 目标")
	}
	if !ProbeTargetOK(pathfetch, raw) {
		t.Fatalf("pathfetch 应探测 raw 目标")
	}
	// 前缀源不受影响：全部 raw 目标照测。
	if !ProbeTargetOK(prefix, codeload) {
		t.Fatalf("前缀源应照常探测 codeload 目标")
	}
	if !ProbeTargetOK(prefix, raw) {
		t.Fatalf("前缀源应照常探测 raw 目标")
	}
}

// TestSweepSkipsPathFetchCodeload 验证 Sweep 不会为 pathfetch 源排 codeload 探测。
func TestSweepSkipsPathFetchCodeload(t *testing.T) {
	p := NewPool()

	type hit struct {
		mirrorID string
		host     string
	}
	var mu sync.Mutex
	var hits []hit
	p.probe = func(ctx context.Context, m config.Mirror, t config.ProbeTarget, maxBytes int64) (Result, error) {
		mu.Lock()
		hits = append(hits, hit{m.ID, t.Host})
		mu.Unlock()
		return Result{OK: true, LatencyMS: 10, ThroughputKBps: 100}, nil
	}

	mirrors := []config.Mirror{
		{ID: "xget", Kind: config.KindPathFetch, URL: "https://xget.example/gh", Enabled: true},
		{ID: "pref", Kind: config.KindPrefix, URL: "https://ghproxy.example", Enabled: true},
	}
	targets := []config.ProbeTarget{
		{Host: "raw.githubusercontent.com", Path: "/github/gitignore/main/Go.gitignore", Category: config.CatRaw},
		{Host: "codeload.github.com", Path: "/github/gitignore/tar.gz/refs/heads/main", Category: config.CatRaw},
	}

	res := p.Sweep(context.Background(), mirrors, targets, 65536)
	if res == nil {
		t.Fatalf("Sweep 返回 nil（可能检测到并发中）")
	}

	for _, h := range hits {
		if h.mirrorID == "xget" && h.host == "codeload.github.com" {
			t.Fatalf("pathfetch 源被安排了 codeload 探测")
		}
	}
	// pathfetch 的 raw 探测与前缀源的两类探测都应在。
	var xgetRaw, prefRaw, prefCodeload bool
	for _, h := range hits {
		switch {
		case h.mirrorID == "xget" && h.host == "raw.githubusercontent.com":
			xgetRaw = true
		case h.mirrorID == "pref" && h.host == "raw.githubusercontent.com":
			prefRaw = true
		case h.mirrorID == "pref" && h.host == "codeload.github.com":
			prefCodeload = true
		}
	}
	if !xgetRaw || !prefRaw || !prefCodeload {
		t.Fatalf("预期探测缺失: xgetRaw=%v prefRaw=%v prefCodeload=%v", xgetRaw, prefRaw, prefCodeload)
	}
}

// TestHttpProbe429IsSkip 验证 429（限流）按「不适用」处理，不记源失败。
func TestHttpProbe429IsSkip(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	p := NewPool()
	m := config.Mirror{ID: "m1", Kind: config.KindPrefix, URL: srv.URL}
	tg := config.ProbeTarget{Host: "github.com", Path: "/a/b/c", Category: config.CatWeb}

	_, err := p.httpProbe(context.Background(), m, tg, 65536)
	if !errors.Is(err, errProbeSkip) {
		t.Fatalf("429 应返回 errProbeSkip，实际: %v", err)
	}
}

// TestHttpProbe404IsFailure 验证 404 仍记失败（镜像真的服务不了该路径）。
func TestHttpProbe404IsFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	p := NewPool()
	m := config.Mirror{ID: "m1", Kind: config.KindPrefix, URL: srv.URL}
	tg := config.ProbeTarget{Host: "github.com", Path: "/a/b/c", Category: config.CatWeb}

	_, err := p.httpProbe(context.Background(), m, tg, 65536)
	if err == nil || errors.Is(err, errProbeSkip) {
		t.Fatalf("404 应记失败而非跳过，实际: %v", err)
	}
}

// TestHttpProbe403APIIsSkip 验证 api.github.com 的 403（限流）按「不适用」处理。
func TestHttpProbe403APIIsSkip(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	p := NewPool()
	m := config.Mirror{ID: "m1", Kind: config.KindPrefix, URL: srv.URL}
	tg := config.ProbeTarget{Host: "api.github.com", Path: "/meta", Category: config.CatWeb}

	_, err := p.httpProbe(context.Background(), m, tg, 65536)
	if !errors.Is(err, errProbeSkip) {
		t.Fatalf("api.github.com 的 403 应返回 errProbeSkip，实际: %v", err)
	}
}

// TestHttpProbe403OtherHostIsFailure 验证其他域名的 403 仍记失败。
func TestHttpProbe403OtherHostIsFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	p := NewPool()
	m := config.Mirror{ID: "m1", Kind: config.KindPrefix, URL: srv.URL}
	tg := config.ProbeTarget{Host: "github.com", Path: "/favicon.ico", Category: config.CatWeb}

	_, err := p.httpProbe(context.Background(), m, tg, 65536)
	if err == nil || errors.Is(err, errProbeSkip) {
		t.Fatalf("非 api 域名的 403 应记失败，实际: %v", err)
	}
}

// TestHttpProbeUsesBrowserUA 验证探测 UA 与真实转发一致。
func TestHttpProbeUsesBrowserUA(t *testing.T) {
	uaCh := make(chan string, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		uaCh <- r.Header.Get("User-Agent")
		_, _ = w.Write(make([]byte, 16<<10))
	}))
	defer srv.Close()

	p := NewPool()
	m := config.Mirror{ID: "m1", Kind: config.KindPrefix, URL: srv.URL}
	tg := config.ProbeTarget{Host: "github.com", Path: "/favicon.ico", Category: config.CatWeb}

	res, err := p.httpProbe(context.Background(), m, tg, 65536)
	if err != nil || !res.OK {
		t.Fatalf("探测应成功，实际 res=%+v err=%v", res, err)
	}
	if got := <-uaCh; got != config.DefaultUserAgent {
		t.Fatalf("探测 UA 应与真实转发一致，实际: %q", got)
	}
}

// TestProbeTargetOKCloneOnlyGitClone 验证仓库传输目标只测 git 镜像源。
func TestProbeTargetOKCloneOnlyGitClone(t *testing.T) {
	git := config.Mirror{ID: "kkgit", Kind: config.KindGitClone, URL: "https://kkgithub.example/"}
	prefix := config.Mirror{ID: "pref", Kind: config.KindPrefix, URL: "https://ghproxy.example"}
	clone := config.ProbeTarget{
		Host: "github.com", Path: "/a/b.git/info/refs?service=git-upload-pack", Category: config.CatClone,
	}

	if !ProbeTargetOK(git, clone) {
		t.Fatalf("git 镜像源应探测仓库传输目标")
	}
	if ProbeTargetOK(prefix, clone) {
		t.Fatalf("前缀源不应被仓库传输目标惩罚")
	}
}

// TestMirrorProbeTargets 验证测速目标集合的构成。
func TestMirrorProbeTargets(t *testing.T) {
	targets := config.MirrorProbeTargets()

	seen := make(map[string]bool, len(targets))
	hasClone := false
	for _, tg := range targets {
		key := tg.Host + tg.Path
		if seen[key] {
			t.Fatalf("探测目标重复: %s", key)
		}
		seen[key] = true
		if tg.Host == "objects.githubusercontent.com" {
			t.Fatalf("objects 根路径恒为 404，不应作为测速目标")
		}
		if tg.Category == config.CatClone {
			hasClone = true
		}
	}
	if !hasClone {
		t.Fatalf("测速目标缺少 CatClone 项，git 镜像源将无法被探测")
	}

	// DNS 优选目标必须保持每个域名唯一，避免 OptimizeAll 结果互相覆盖。
	dnsHosts := make(map[string]bool)
	for _, tg := range config.DomainProbeTargets() {
		if dnsHosts[tg.Host] {
			t.Fatalf("DNS 优选目标重复域名: %s", tg.Host)
		}
		dnsHosts[tg.Host] = true
	}
}
