# ⚡ gateway: 1.8× faster

`python fa_workload.py` went from **1.82s** to **1.04s** (median of 5 runs each, original and Rust interleaved).

![fast-anything report](report.svg)

| function | per call | checked against |
|---|---|---|
| `app.flow_fingerprint.fingerprint` | **2.9×** (10.3ms → 3.5ms) | 422/422 recorded real calls |

The original code stays in place: set `FAST_ANYTHING_DISABLE=1` to run it, or `fast-anything disable <id>` to remove the switch.

<sub>Made with [fast-anything](https://github.com/EL4CTEO/fast-anything)</sub>
