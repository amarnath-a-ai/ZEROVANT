# Real-World Workflow Fixtures Provenance and Sources

This directory contains 10 unmodified, authentic GitHub Actions workflow configurations collected from prominent open-source repositories on GitHub.

| File Name | Upstream Repository | Workflow Path | Reference / Version | License | Security Characteristics / Notes |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `actions_checkout_check_dist.yml` | `https://github.com/actions/checkout` | `.github/workflows/check-dist.yml` | `v4.1.1` | MIT | Official GitHub action; uses unpinned `@v4` refs internally; demonstrates standard runner tests. |
| `pallets_flask_tests.yaml` | `https://github.com/pallets/flask` | `.github/workflows/tests.yaml` | `3.0.3` | BSD-3-Clause | Standard Python test matrix workflow; uses `.yaml` extension; uses `@v4` tags. |
| `pydantic_pydantic_ci.yml` | `https://github.com/pydantic/pydantic` | `.github/workflows/ci.yml` | `v2.7.1` | MIT | Complex enterprise CI matrix; demonstrates permissions blocks and multi-os runners. |
| `fastapi_fastapi_test.yml` | `https://github.com/fastapi/fastapi` | `.github/workflows/test.yml` | `0.111.0` | MIT | Extensive Python test pipeline; unpinned third-party actions; matrix jobs. |
| `pytest_dev_pytest_test.yml` | `https://github.com/pytest-dev/pytest` | `.github/workflows/test.yml` | `8.2.0` | MIT | Core pytest test matrix; tests cross-platform execution (Linux, Windows, macOS). |
| `urllib3_urllib3_ci.yml` | `https://github.com/urllib3/urllib3` | `.github/workflows/ci.yml` | `2.2.1` | MIT | Highly secured network client pipeline; demonstrates least-privilege permissions and pinned tooling. |
| `cli_cli_deployment.yml` | `https://github.com/cli/cli` | `.github/workflows/deployment.yml` | `v2.49.0` | MIT | Official GitHub CLI deployment pipeline; demonstrates packaging, signing, and environment gates. |
| `expressjs_express_ci.yml` | `https://github.com/expressjs/express` | `.github/workflows/ci.yml` | `4.19.2` | MIT | Node.js ecosystem benchmark CI; unpinned `@v3`/`@v4` actions; simple push/PR triggers. |
| `psf_black_test.yml` | `https://github.com/psf/black` | `.github/workflows/test.yml` | `main` | MIT | Python code formatting test suite; demonstrates Python version matrix and caching. |
| `pallets_click_tests.yaml` | `https://github.com/pallets/click` | `.github/workflows/tests.yaml` | `main` | BSD-3-Clause | Pallets ecosystem CLI library test suite; tests multi-OS and Python versions. |

All files were fetched directly from their respective upstream repositories via `raw.githubusercontent.com`.

