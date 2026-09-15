# Protected services lab

This directory contains intentionally simple local targets for exercising the SIEM collector.
They are isolated demo services and must not be exposed to the public internet.

- `flask_target`: Flask service on port 8081
- `django_target`: Django service on port 8082

Run the complete lab with `python start.py --demo` from the project root. The public
ports 80, 8081 and 8082 terminate at OWASP CRS gateways in Detection Only mode;
the application containers are reachable only through those gateways.

Application access logs are under `protected_services/logs/<name>/access.jsonl`.
WAF audit logs are under `protected_services/logs/waf/<name>/audit.jsonl` and are
ingested by the same SIEM collector. Stop the lab with `python stop.py --docker`.
