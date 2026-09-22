# collector-parser-demo

Two cloud-to-cloud collectors, one YAML-driven parser, one normalized
output model. Built as a focused refresher on the pattern: pull from a
third-party API (JSON or XML), map its fields onto a target data model via
a declarative YAML mapping, and fail loudly (not silently) when the
upstream shape drifts.

## Sources

- **NVD CVE API 2.0** (JSON) — `collectors/nvd_cve.py`. Public, no key
  required for light use, rate-limited to 5 req/30s unauthenticated.
- **SANS Internet Storm Center RSS feed** (XML) — `collectors/sans_isc_xml.py`.
  Public, unauthenticated, parsed with `defusedxml` (XXE-safe).

Both are described further in `metadata/*.yaml` — source URL, auth, rate
limits, and the output schema they map to.

## Design

- `collectors/base.py` — one shared `requests.Session` factory with retry/
  backoff (`urllib3.Retry`, respects `Retry-After`, retries 429/5xx) and
  bounded connect/read timeouts. Both collectors mount it rather than
  rolling their own retry logic.
- `parsers/mapper.py` — a small interpreter for YAML mapping files
  (`mappings/*.yaml`): dotted source paths (numeric segments index into
  lists), typed coercion, and a `MappingError` raised on a missing required
  field or failed coercion — never a silently-null field where the schema
  says one is required.
- `parsers/normalize.py` — wires the mapper output plus source-specific
  list handling (`references`) into `parsers.models.SecurityAdvisory`, the
  shared normalized shape both sources produce.

Sync HTTP (`requests`), not async: each collector run is a single-source
pull with no concurrent fan-out — async would add complexity this shape
doesn't need. NVD's own tight rate limit (5 req/30s) would make concurrency
counterproductive here regardless.

## Data Flow

```text
NVD API (JSON)              SANS RSS (XML)
    ↓                             ↓
collectors/nvd_cve.py    collectors/sans_isc_xml.py
    ↓                             ↓
fetch_cves()             fetch_feed() → parse_items()
    ↓                             ↓
     ─────────────┬───────────────
                  ↓
          parsers/normalize.py
                  ↓
     ┌───────────────────────────┐
     │ cve_to_advisory()         │
     │ rss_item_to_advisory()    │
     └───────────────────────────┘
                  ↓
         YAML mapping applied
         (mappings/*.yaml)
                  ↓
         parsers/mapper.py
         • Walk dotted paths
         • Type coercion
         • Fail on missing required fields
                  ↓
      SecurityAdvisory (normalized)
      • external_id
      • title
      • description
      • published_at
      • severity (optional)
      • cvss_score (optional)
      • references (list of URLs)
      • source (nvd_cve or sans_isc)
```

## Design Principles

**Declarative field mapping**: Transformations live in YAML, not Python code.
Adding a new source requires one collector module + one mapping file; existing
logic is untouched. No need to change the mapper or normalizer.

**Fail loudly on data drift**: Missing required fields or type coercion
failures raise `MappingError` immediately with the source path and value. The
system never silently substitutes null where the schema expects a value.

**Centralized resilience**: Retry logic, exponential backoff, jitter, timeouts,
and `Retry-After` header respect live in `collectors/base.py`. Both collectors
inherit this behavior without duplication; transient failures (429, 5xx) are
absorbed and retried; permanent failures surface clearly.

**Separation of concerns**: Each module owns one responsibility:

- **Collectors**: fetch raw data from an API or feed
- **Mapper**: walk nested structures and coerce types per a declarative schema
- **Normalizer**: bridge source-specific quirks (array references vs. single link) and call the mapper; assemble into the shared model
- **Models**: define the normalized shape; validate with Pydantic

**Performance**: Sync HTTP only (no async overhead for single-source pulls);
respects upstream rate limits; bounded connect/read timeouts prevent hangs.

## Integration Notes

**Rate limits**: NVD is rate-limited to 5 req/30s (unauthenticated); SANS has
no published limit but the shared retry policy handles transients. Both
require network access; fixtures are provided for offline testing.

**Data quality**: NVD descriptions are multilingual (en, es); mapper extracts
the first one. SANS ISC lacks CVSS scores; `severity` and `cvss_score` fields
remain null. Both sources are mutable; re-runs may find different data for the
same advisory.

## CLI

A Typer-based command-line tool for fetching advisories from sources and
querying the SQLite database.

```bash
# Fetch NVD CVEs (default: 20 results, saves to advisories.db)
uv run python cli.py fetch-nvd --limit 2

# Fetch SANS ISC RSS feed
uv run python cli.py fetch-sans

# List stored advisories
uv run python cli.py list-advisories-cmd --source nvd_cve

# Use custom database path
uv run python cli.py fetch-nvd --db /path/to/custom.db
```

Results are persisted to SQLite with automatic deduplication by (external_id, source).
