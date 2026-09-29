# Reserved

The web service renders its pages on the server and uses no JavaScript. See `docs/architecture.md`.

This directory is kept for a possible browser application later. If one is built, it needs a
JSON API first, and that API needs the same tenant isolation tests as the pages have today
(`tests/web/test_tenancy.py`).
