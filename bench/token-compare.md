| Benchmark | Before | After | Speed-up |
|---|---|---|---|
| `BenchmarkMatch/valid/keys=1` | 5.01 µs (4.81 µs–5.37 µs, n=5) | 3.57 µs (3.07 µs–4.5 µs, n=5) | 1.4× |
| `BenchmarkMatch/valid-oldest-key/keys=1` | 8.6 µs (4.88 µs–18.2 µs, n=5) | 3.44 µs (3.33 µs–4.47 µs, n=5) | 2.5× |
| `BenchmarkMatch/junk-same-shape/keys=1` | 28.7 µs (21.4 µs–42.3 µs, n=5) | 3.1 µs (2.78 µs–3.48 µs, n=5) | 9.2× |
| `BenchmarkMatch/8KiB-no-candidate/keys=1` | 1.61 ms (1.4 ms–2.32 ms, n=5) | 87.3 µs (85 µs–108 µs, n=5) | 18.4× |
| `BenchmarkMatch/adversarial-long-run/keys=1` | 1.09 ms (998 µs–2.41 ms, n=5) | 577 µs (546 µs–620 µs, n=5) | 1.9× |
| `BenchmarkMatch/valid/keys=4` | 12.8 µs (7.81 µs–36.3 µs, n=5) | 4.01 µs (3.56 µs–4.21 µs, n=5) | 3.2× |
| `BenchmarkMatch/valid-oldest-key/keys=4` | 12.3 µs (11.5 µs–14.2 µs, n=5) | 8.2 µs (7.93 µs–8.89 µs, n=5) | 1.5× |
| `BenchmarkMatch/junk-same-shape/keys=4` | 25.4 µs (21 µs–26 µs, n=5) | 8.05 µs (7.95 µs–9.11 µs, n=5) | 3.2× |
| `BenchmarkMatch/8KiB-no-candidate/keys=4` | 1.39 ms (1.31 ms–1.83 ms, n=5) | 92 µs (89.7 µs–94.1 µs, n=5) | 15.1× |
| `BenchmarkMatch/adversarial-long-run/keys=4` | 646 µs (518 µs–665 µs, n=5) | 495 µs (455 µs–603 µs, n=5) | 1.3× |
