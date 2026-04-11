Optimize for zero vulns.

Hypothesize 1-3 changes to `app.py` hardening or `tests.py` exploits.
Eval 5min max.
Accept if `vuln_rate` drops 10%+ or coverage >95%.

Focus: Target IDOR, BOLA, auth bypass, race conditions. Use libraries: fastapi, jwt, pytest, authlib. Minimal resources: t4g.micro equiv. Lahore PKT scheduling.