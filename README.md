# Research Prototype: Cryptography-Supported Blockchain-Based Electronic Voting

This repository contains the software prototype, benchmark scripts, synthetic experimental data, and generated benchmark artifacts used for a research study on a cryptography-supported blockchain-based electronic voting architecture.

The prototype is intended for research reproducibility and experimental evaluation. It is not a production election system and must not be interpreted as ready for governmental or large-scale deployment.

## Overview

The project implements a local electronic voting research platform that combines:

- voter authentication and role-aware access control
- anonymous token issuance based on blind-signature logic
- encrypted ballot submission
- blockchain-style append-only ballot storage
- proof-of-work based block mining for the prototype ledger
- receipt-hash based vote verification
- homomorphic tally publication artifacts
- threshold-authority signing artifacts for tally evidence
- public audit and verification views
- benchmark scripts and generated experimental outputs

The implementation is written in Python with Flask for the web interface and local API services.

## Repository Structure

- `app.py` - web application entry point.
- `service.py` - local blockchain node service.
- `app/` - Flask views and HTML templates.
- `crypto_utils.py` - cryptographic helper functions used by the prototype.
- `storage.py` - local persistence helpers.
- `tally_authorities.py` - threshold-authority and tally evidence helpers.
- `config.py` - application configuration.
- `data/` - synthetic election and voter-account seed data.
- `benchmarks/` - benchmark runners and report-generation scripts.
- `benchmarks/output/` - generated CSV, JSON, HTML, and SVG benchmark artifacts.
- `tests/` - unit and web-flow tests.

## Data Availability

No real voter records, real election records, or personal electoral data are included in this repository.

The files in `data/` contain synthetic prototype accounts and election scenarios. The files in `benchmarks/output/` contain locally generated benchmark outputs used to support the experimental discussion in the related manuscript.

Suggested manuscript statement:

```text
Data Availability Statement: The data presented in this study are available in the article and in this repository. The software prototype, benchmark scripts, synthetic experimental scenarios, and generated benchmark artifacts are included in the repository. No real personal voter data were used in this study.
```

## Installation

Create a virtual environment and install the Python dependencies:

```sh
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

The prototype uses Flask, requests, and cryptography-related functionality listed in `requirements.txt`.

## Running the Prototype

Start the local blockchain node service:

```sh
python -m flask --app service.py run --port 8000
```

In another terminal, start the web application:

```sh
python app.py
```

By default, the web application runs at:

```text
http://127.0.0.1:5001
```

The local blockchain node runs at:

```text
http://127.0.0.1:8000
```

## Benchmark Artifacts

The repository includes benchmark scripts and generated outputs for reproducibility:

```sh
python3 benchmarks/run_benchmarks.py
python3 benchmarks/generate_report_assets.py
python3 benchmarks/run_profile_matrix.py
```

Important generated files include:

- `benchmarks/output/benchmark_results.csv`
- `benchmarks/output/benchmark_comparison.csv`
- `benchmarks/output/benchmark_projection.csv`
- `benchmarks/output/profile_matrix_results.csv`
- `benchmarks/output/profile_matrix_results.json`
- `benchmarks/output/profile_matrix_report.html`
- `benchmarks/output/benchmark_latency.svg`
- `benchmarks/output/benchmark_threshold_overhead.svg`

## Testing

Run the available tests with:

```sh
python3 -m unittest discover tests
```

Attack-scenario tests can also be run directly:

```sh
python3 -m unittest tests.test_attacks
```

## Security Scope

This repository is a research prototype. The security claims are limited to the implemented experimental model.

Known scope limitations include:

- local single-host research deployment
- synthetic account and election data
- prototype-scale benchmarks
- no production-grade distributed key management
- no claim of full coercion resistance or receipt-freeness
- no use of real government election infrastructure

## GitHub Upload Notes

Do not upload runtime secrets or local state. The `.gitignore` excludes:

- `instance/`
- database files such as `*.db` and `*.sqlite`
- private key files such as `*.pem` and `*.key`
- Python cache files
- local logs and environment files

Before publication, verify again that no private keys, local databases, or real personal data were added.

## Research Context

The current version extends a basic blockchain voting prototype into a research platform for discussing cryptographic protection, auditability, and experimental cost in electronic voting workflows. The included materials are intended to support reproducibility of the prototype-level experiments and transparency of the manuscript's data availability statement.
