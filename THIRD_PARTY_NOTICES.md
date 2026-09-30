# Third-party notices

Perimeterwatch is licensed under Apache-2.0. It uses the programs and data below. None of
them is modified, and none is linked into Perimeterwatch: each external tool is a separate
program that Perimeterwatch downloads, verifies and runs.

The exact versions and checksums are in `src/perimeterwatch/tools/manifest.toml`.

## Tools run as separate programs

| Tool | Licence | Source |
|---|---|---|
| subfinder | MIT | https://github.com/projectdiscovery/subfinder |
| httpx | MIT | https://github.com/projectdiscovery/httpx |
| tlsx | MIT | https://github.com/projectdiscovery/tlsx |
| naabu | MIT | https://github.com/projectdiscovery/naabu |
| nuclei | MIT | https://github.com/projectdiscovery/nuclei |
| nuclei-templates (data) | MIT | https://github.com/projectdiscovery/nuclei-templates |
| betterleaks | MIT | https://github.com/betterleaks/betterleaks |
| S3Scanner | MIT | https://github.com/sa7mon/S3Scanner |
| ssh-audit | MIT | https://github.com/jtesta/ssh-audit |
| trufflehog | AGPL-3.0-only | https://github.com/trufflesecurity/trufflehog |

### trufflehog and the AGPL

trufflehog is licensed under the GNU Affero General Public License, version 3. The container
image built from `deploy/Dockerfile` includes the unmodified trufflehog binary as published
by its authors. Its complete source code, for the exact version included, is available at
the address above under the release tag named in the manifest. The licence text is at
https://www.gnu.org/licenses/agpl-3.0.txt

Perimeterwatch does not modify trufflehog and does not link against it. If you change
trufflehog and offer the result to others, including over a network, the AGPL requires you
to publish your changes.

## Data sources

| Source | Terms that matter here |
|---|---|
| Have I Been Pwned | Breach data is licensed CC BY 4.0 and is attributed wherever it is shown. Results are shown only to the verified owner of a domain |
| crt.sh | Public certificate transparency search. Requests are spaced out and cached |
| GitHub API | Public data only, read with a token supplied by the operator |
| MetaMask eth-phishing-detect | Public blocklist of phishing domains, under the DBAD Public License 1.2, which asks for attribution. Findings that use it say so |
| polkadot-js/phishing | Public blocklist of phishing domains, under the Apache License 2.0. Findings that use it say so |
| Phishing.Database | Public list of active phishing domains, under the MIT licence. Read line by line, only matches are kept. Findings that use it say so |
| RDAP (IANA bootstrap and registry servers) | The public registration lookup that replaced WHOIS. Contact details of registrants are never read |
| Internet Archive Wayback Machine | Public index of archived addresses. The addresses themselves are never fetched |
| Hudson Rock | Off by default. No terms are published for this endpoint: get written permission before switching it on in a hosted service |

## Python libraries

Installed from PyPI under their own licences. The full list with versions is in `uv.lock`.
The main ones: pydantic, SQLAlchemy, Alembic, FastAPI, Uvicorn, httpx, dnspython, checkdmarc,
dnstwist, cryptography, Jinja2, Typer, structlog, tldextract, PyYAML, eth-utils.

`src/perimeterwatch/data/takeover_services.json`, `dkim_selectors.txt` and
`tech_keywords.json` were written for this project.
