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
- **New record types**: Add to `RECORD_TYPES` list (line 31)
- **New DNSSEC types**: Add to `DNSSEC_TYPES` list (line 34)
- **New special records**: Add query in `query_special_records()` following the `_dmarc.{fqdn}` pattern

### Error Handling

DNS queries distinguish between expected and unexpected failures:
```python
try:
    answers = resolver.resolve(fqdn, rtype)
except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
    pass  # Expected - record doesn't exist
except dns.exception.Timeout:
    query_errors.append(...)  # Track for warning
```

- `NXDOMAIN`, `NoAnswer`, `NoNameservers` - silent (expected for non-existent records)
- `Timeout` and other exceptions - tracked in `query_errors` list, shown with `--verbose`

### Output Structure

All records use this dict structure:
```python
{"domain": str, "type": str, "value": str, "ttl": int}
```

Optional fields:
- `"source": "AXFR"` - for zone transfer results
- `"is_wildcard": True` - for wildcard records
- `"is_dnssec": True` - for DS/DNSKEY records

### Comparison Output

`detect_changes()` returns:
- `old_only` - records truly removed (domain+type not in new)
- `new_only` - records truly added (domain+type not in old)
- `changed` - same domain+type, different values
- `unchanged` - identical records

## Key Functions

- `enumerate_domains()` - Main enumeration loop
- `query_record()` - Single DNS query wrapper with error tracking
- `query_special_records()` - DMARC, DKIM, MTA-STS, BIMI, TLSA queries
- `query_wildcard()` - Wildcard record queries
- `query_dnssec()` - DS/DNSKEY queries
- `detect_changes()` - Groups records by (domain, type) to find changes
- `compare_dns()` - Diff between two nameservers
