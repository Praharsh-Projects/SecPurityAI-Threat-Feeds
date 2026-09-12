# SecPurityAI Public Threat Feeds

Public-only CISA KEV and NIST NVD processing for SecPurityAI. This repository does
not contain the private application, tenant records, credentials or model prompts.

## Run locally

Python 3.11+; the ingestion process uses only the standard library.

```sh
python3 -m unittest discover -s tests -v
python3 feed.py --sqlite catalog.db --source cisa-kev
python3 feed.py --sqlite catalog.db
```

Repeated runs resume NVD pages and preserve the last published data on failure.
Rows are staged under an unpublished generation. An atomic publication trigger
switches visibility only after its summary exists. Each page is a validated
publication unit; incomplete NVD windows remain visibly incomplete and do not
advance the successful-source freshness timestamp.

## Hosted refresh

A Cloudflare Cron Worker dispatches `sync.yml` on `main` every six hours. The
workflow runs only on manual or authenticated dispatch, never on pull requests.
Standard GitHub Linux runners for this public repository avoid private Actions
minute charges. No paid/larger runners or model inference are used here.

Required environment secrets: `CLOUDFLARE_ACCOUNT_ID`, `PUBLIC_D1_DATABASE_ID`,
`CLOUDFLARE_API_TOKEN` (minimum available D1 write permissions), and optionally
`NVD_API_KEY`. Cloudflare's dispatcher holds a separate repository-restricted
GitHub token with Actions write permission. Never put either token in source.

Provision `schema.sql` once using Wrangler before enabling dispatch. Initial
NVD bootstrap can span multiple runs/days because writes are conservatively
capped at 60,000 per UTC day including estimated index and metadata overhead.
No additional paid capacity is purchased when a limit is reached.

## Provenance

- CISA: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- NIST NVD: https://nvd.nist.gov/developers/vulnerabilities

This product uses the NVD API but is not endorsed or certified by the NVD.
Retain source attribution. CVSS is severity, not exploitation probability or
proof of device exposure. CISA deadlines are not universal patch deadlines.
No original upstream licensing or attribution rights are changed by this repo.

The writer lease prevents overlapping manual/workflow imports. A successful job
may report `budget_paused`: this means the conservative daily allocation stopped
further writes, not that NVD was fully imported. The saved cursor resumes after
UTC midnight. Expired leases recover after 45 minutes if a job is terminated.
Superseded CVE versions are pruned in bounded batches while preserving the current
and previous publication for rollback. Product/CVE/vendor search uses indexes.
