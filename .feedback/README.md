# Feedback task starting environment

Upstream: https://github.com/tlsfuzzer/tlslite-ng
Upstream commit: `7e95ea1a86c0d42d8d931ff14134d31f01ce1d76`
Prepared on macOS with CPython 3.12.11. No external database, queue, or cloud account is required.
The dependency file pins the installed runtime and test packages for the selected baseline. It is not a claim that all optional upstream test suites are installed.

From the repository root:

```sh
export NO_INTERNET=1 TZ=UTC UV_NO_CONFIG=1

uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
.venv/bin/python -m pytest -q -o addopts= unit_tests/test_tlslite_messages.py unit_tests/test_tlslite_extensions.py
```

Scope note: The scope is the command below, not all optional upstream integrations.

Observed baseline (2026-11-11): `586 passed, 1 skipped in 0.48s`
Whole-command wall time: 0.832 seconds, exit code 0. This is one local measurement, not a runtime guarantee. The first install is excluded.

This seed adds preparation metadata only. Application sources and upstream tests are unchanged; there is no task solution in this commit.
