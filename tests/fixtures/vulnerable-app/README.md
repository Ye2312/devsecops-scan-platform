# vulnerable-app (test fixture)

Deliberately insecure toy app. Never run this — it exists only as a fixed,
reproducible scan target so the platform's output can be checked against a
known answer instead of an unpredictable live repository.

## Known findings (ground truth)

**SAST (`app/main.py`)**
- hardcoded secret (`API_SECRET_KEY`)
- SQL injection (`get_user`, string-concatenated query)
- RCE via `eval()` (`calc`)
- command injection via `os.system()` (`ping`)
- Flask debug mode + bind-all-interfaces (`app.run`)

**SCA (`requirements.txt`)**
- outdated `Flask`, `PyYAML`, `requests`, `Jinja2` — each with known CVEs

**Secrets (`.env`)**
- AWS access key + secret key — fake but correctly-formatted values, not
  AWS's well-known published example keys, which real scanners specifically
  allowlist as known-safe and therefore won't flag
- a plaintext database password

**IaC (`Dockerfile`, `k8s.yaml`)**
- root base image with no `USER` instruction (container runs as root)
- `ADD` used where `COPY` would do — note Trivy's DS-0005 exempts the
  remote-URL and archive forms, so only the local-path form is detected
- no `HEALTHCHECK` defined
- secret baked into an image layer via `ENV`
- `privileged: true` container in the Kubernetes manifest, plus the absent
  hardening Trivy reports alongside it (no resource limits, no seccomp
  profile, no dropped capabilities, writable root filesystem)
