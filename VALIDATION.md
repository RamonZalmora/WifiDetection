# Validation record

Executed in the Linux cloud environment on 2026-10-24, using Python 3.12.14.

- Dependency installation with `requirements-dev.txt` and `requirements.lock`: passed.
- `python -m pip check`: passed, no broken requirements.
- `python -m pytest -q`: **27 passed**, including live subprocess startup, authenticated existing-instance reuse, port-conflict failure, and live shutdown. One upstream Starlette/AnyIO deprecation warning was reported.
- IEEE WPA PMK known-answer vector: passed as part of the suite.
- Correct/incorrect EAPOL MIC candidates, independent re-derivation, bounded verification, cancellation, strict import validation, SQLite password exclusion, report escaping, sensitive-export controls, and browser-request guards: passed as part of the suite.
- Real Chromium/Playwright browser smoke: passed after the final cryptographic changes. It created an authorized synthetic project, rejected the first candidate, verified the second candidate, displayed its actual value, exported an HTML report without the password field, checked the honest Linux scanner limitation, navigated the dashboard, and checked mobile document width. No browser JavaScript errors were observed.
- JavaScript syntax and Python compilation checks: passed.
- Server validation used only 127.0.0.1:8765; the validation process exited successfully after authenticated shutdown.

Not executed: Windows 11 physical adapter enumeration/scanning, real router exchange interoperability, Windows EXE packaging, packaged operation without Python, Windows privacy-denial behavior, and Windows hardware/driver compatibility. Mock adapter data is used only by automated tests. Generated exchanges are synthetic; no actual router password was recovered or router connection established during validation.

The README contains the required Windows acceptance checklist. This record validates development capabilities in the current Linux instance; it is not Windows certification, proof of publication, or proof of restoration in a new cloud task.
