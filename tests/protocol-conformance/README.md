# Gateway v1 protocol conformance

`manifest.json` связывает требования с Rust black-box suites. `run_suite.py`
запускает actual implementation и пишет destination-free JSON report. Fuzz target
запускается отдельно nightly; найденный corpus становится постоянным regression
fixture.
