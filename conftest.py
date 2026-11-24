# The tests are plain scripts (`python3 <name>_test.py`) and also import cleanly under pytest.
# The integration test fetches promptfoo from npm and calls a runner, so a bare `pytest` skips it.
# Run it on purpose: python3 run-n_integration_test.py
collect_ignore = ["run-n_integration_test.py"]
