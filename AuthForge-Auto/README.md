# AuthForge-Auto

AuthForge-Auto is a local testbed for evaluating autonomous security patching loops against API endpoints. I built this to test how well an LLM agent can identify and write logic patches for common web vulnerabilities like BOLA, IDOR, and race conditions, drawing on Andrej Karpathy's autoresearch workflow.

## Overview

The setup relies on three components:
1. `app.py`: A vulnerable FastAPI web server.
2. `tests.py`: A pytest runner that generates 1000 randomized attack payloads and outputs a calculated vulnerability rate (`vuln_rate`) and test coverage metric.
3. `program.md`: The system prompt driving the agent loop.

The agent reads `program.md`, analyzes the output of `tests.py`, and modifies `app.py` or the test cases themselves. The loop terminates when the test runner reports a 0.00 `vuln_rate`.

## Setup

Requires Python 3.10 or newer.

1. Clone the repository and move into the directory:
   ```bash
   git clone https://github.com/f2025408135-cyber/AuthForge-Auto.git
   cd AuthForge-Auto
   ```

2. Install the required packages:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

To start the local target:
```bash
uvicorn app:app --reload
```

To run the scorer:
```bash
python tests.py
```

The scorer outputs a raw ratio of successful exploits against the total payloads generated, followed by the pytest-cov coverage output.

## Known Limitations

The `app.py` target currently uses an hardcoded 11-byte JWT secret (`supersecret`), which throws `InsecureKeyLengthWarning` during test runs. Since the app is an intentional dummy target meant to be run locally, this is a known state and does not affect the exploit logic routing.

## License

MIT License. See LICENSE for exact terms.