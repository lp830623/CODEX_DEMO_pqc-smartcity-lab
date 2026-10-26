# Results

These files were produced by the benchmark harness in this repository.
Regenerate them with `python -m pqc_smartcity bench --output results` and
`python -m pqc_smartcity charts --results results`.

| File | Contents |
| --- | --- |
| `environment.json` | Host, library versions, iteration count, method note |
| `timings.csv` | Median, mean, stdev, p95, min, max for each operation |
| `samples.csv` | Per-iteration samples behind the summaries |
| `sizes.csv` | Handshake and telemetry sizes by suite and profile |
| `primitives.csv` | Measured object sizes, with the FIPS 203/204 lengths beside ML-KEM and ML-DSA |
| `summary.md` | The tables quoted by the main README |
| `charts/` | Matplotlib figures |

Absolute milliseconds belong to this machine and to CPython. The comparison
across suites is the result the harness is built to support.
