# Verification record

Date: 2026-09-28. Tested locally on Linux with Python 3.12.14.

| Check | Result |
| --- | --- |
| unittest discovery | 50 tests passed |
| Ruff lint | Passed |
| Ruff format check | Passed |
| Source distribution and universal Python wheel build | Passed |
| Wheel installation in isolated virtual environment | Passed |
| Installed CLI demo outside source checkout | Passed |
| Chromium report: error filter, search and duration ordering | Passed |
| Mobile 390px layout: no document-width overflow | Passed |
| Desktop and mobile screenshot review | Completed |
| Source input remains unchanged | Covered by regression test |
| Canaries absent from HAR, audit and HTML | Covered by regression test |

The README image is a rendered preview of the synthetic demo report, kept in sync with the report renderer.

CI is configured for Python 3.10, 3.12 and 3.13 on Linux, Windows and macOS.
Those hosted jobs have not run yet; local testing does not establish their status.
Import into Chrome/Firefox DevTools, huge-capture performance and a broad corpus
of producer-specific HAR files remain unverified. No independent audit, security
certification, benchmark superiority or code-coverage percentage is claimed.

Development dependencies and build backend are not runtime dependencies.
No package, GitHub repository or release has been published during preparation.
