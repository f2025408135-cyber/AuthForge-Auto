# MultiUserMutant

MultiUserMutant is an automated API testing toolkit designed to identify Broken Object Level Authorization (BOLA) and Broken Function Level Authorization (BFLA) vulnerabilities. The system parses OpenAPI specifications and constructs multi-user state-chaining workflows to test endpoint security boundaries. 

## Structure

*   `mutant.py`: Manages the attack workflows. It parses the target OpenAPI specification, generates test hypotheses (simulating different user roles and access tokens), and executes them concurrently using `httpx`.
*   `scorer.py`: Evaluates the HTTP responses from the executed workflows. It flags anomalies such as unexpected 200/201 status codes for unauthorized roles, 500 errors indicating unhandled logic flaws, or significant response size differences.
*   `prompts.md`: Contains the system instructions for generating new test mutations.

## Installation

Requires Python 3.10+.

```bash
git clone https://github.com/f2025408135-cyber/MultiUserMutant.git
cd MultiUserMutant
pip install -r requirements.txt
playwright install
```

## Usage

You can test the tool against a demonstration API:

```bash
python mutant.py
```

The script currently runs against `reqres.in` to demonstrate the request chaining and scoring mechanism.

## License

MIT License. See LICENSE for exact terms.