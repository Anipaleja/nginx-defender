# Benchmark Methodology

Use this page to keep benchmark runs consistent over time.

## Benchmark Categories

1. Build performance
2. Test runtime performance
3. Detection quality
4. Resource footprint

## Standard Benchmark Suite

```bash
# Always run from repository root
/usr/bin/time -p go build -o /tmp/nginx-defender-bench ./cmd/nginx-defender
/usr/bin/time -p go test -count=1 ./cmd/nginx-defender
/usr/bin/time -p go test -count=1 ./internal/detector ./internal/firewall ./internal/metrics
/usr/bin/time -p go test -count=1 ./...
stat -f %z /tmp/nginx-defender-bench
```

## Detection Quality Benchmarks

Use a fixed replay dataset and report:

- True positives
- False positives
- False negatives
- Precision and recall
- p95 detection latency

Suggested format:

| Dataset | TP | FP | FN | Precision | Recall | p95 Latency |
|---|---:|---:|---:|---:|---:|---:|
| baseline-http-logs | - | - | - | - | - | - |
| scanner-heavy | - | - | - | - | - | - |
| mixed-production-sample | - | - | - | - | - | - |

## Resource Benchmarks

Recommended metrics for long runs (15m, 1h):

- CPU percent
- RSS memory
- Goroutine count
- Event throughput per second

Example collection commands:

```bash
# process-level snapshot
ps -o %cpu,rss,etime,command -p "$(pgrep -f nginx-defender | head -n 1)"

# Go runtime benchmarks where available
go test -bench=. -benchmem ./...
```

## Publishing Guidance

- Record machine type and OS.
- Record Go version (`go version`).
- Disable test cache for timed runs (`-count=1`).
- Keep benchmark datasets versioned.
- Update docs/benchmark-results.md after each benchmark session.
