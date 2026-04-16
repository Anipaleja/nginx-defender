# Benchmark Results

This page tracks practical benchmark metrics for nginx-defender. Values below are from local runs and should be compared only across similar machines and workloads.

Last updated: 2026-04-15

## Runtime and Build Benchmarks

| Benchmark | Command | Result |
|---|---|---:|
| Command package tests | `go test ./cmd/nginx-defender` | 3.35s |
| Core engine tests | `go test ./internal/detector ./internal/firewall ./internal/metrics` | 0.33s |
| Full repository tests | `go test ./...` | 0.62s |
| Production binary build | `go build -o /tmp/nginx-defender-bench ./cmd/nginx-defender` | 3.04s |
| Binary size | `stat -f %z /tmp/nginx-defender-bench` | 23,135,506 bytes |

## Detection Quality Snapshot

| System | Detection Time | False Positives | Missed Attacks |
|---|---:|---:|---:|
| nginx-defender | 500.6115ms | 200 | 224 |
| fail2ban-baseline | 2.542us | 0 | 441 |

## Environment Notes

- fail2ban baseline was not installed in this environment during this run.
- Test caching can reduce repeated `go test` wall time.
- For strict comparisons, run with cache disabled: `go test -count=1 ./...`.

## Reproduce Benchmarks

```bash
# Build and test timings
/usr/bin/time -p go test ./cmd/nginx-defender
/usr/bin/time -p go test ./internal/detector ./internal/firewall ./internal/metrics
/usr/bin/time -p go test ./... -count=1
/usr/bin/time -p go build -o /tmp/nginx-defender-bench ./cmd/nginx-defender
stat -f %z /tmp/nginx-defender-bench

# Optional comparison script
bash scripts/benchmark-compare.sh
```
