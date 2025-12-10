# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Single-file Python CLI tool for DNS enumeration. Uses PEP 723 inline script metadata (lines 1-3) to declare `dnspython` dependency. No test suite.

## Run Command

```bash
uv run dns_dump.py example.com
```

See README.md for full usage options.

## Code Patterns

### Adding New Functionality

- **New subdomains**: Add to `SUBDOMAINS` list (line 12)
- **New DKIM selectors**: Add to `DKIM_SELECTORS` list (line 24)
- **New record types**: Add to `RECORD_TYPES` list (line 30)
- **New special records**: Add query in `query_special_records()` following the `_dmarc.{fqdn}` pattern

### Error Handling

DNS queries use silent failure pattern - exceptions are caught and ignored to continue enumeration:
```python
try:
    answers = resolver.resolve(fqdn, rtype)
except Exception:
    pass  # Expected for non-existent records
```

Maintain this pattern for DNS queries. Use explicit error handling only for file I/O and argument validation.

### Output Structure

All records use this dict structure:
```python
{"domain": str, "type": str, "value": str, "ttl": int}
```

AXFR results add `"source": "AXFR"`. Maintain this structure for compatibility with `write_results()`.

## Key Functions

- `enumerate_domains()` - Main enumeration loop
- `query_record()` - Single DNS query wrapper
- `query_special_records()` - DMARC, DKIM, MTA-STS, BIMI, TLSA queries
- `compare_dns()` - Diff between two nameservers
