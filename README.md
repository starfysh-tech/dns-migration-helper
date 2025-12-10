# dns_dump.py

DNS enumeration tool for domain migrations. Queries multiple record types across root domains and common subdomains.

## DNS Migration Workflow

### Step 1: Dump Current DNS Records
Before making any changes, capture all existing DNS records from your current nameservers.

```bash
uv run dns_dump.py --csv domains.txt --output pre_migration
```

Review `pre_migration.json` to understand your current DNS configuration.

### Step 2: Lower TTLs (Optional but Recommended)
If you have high TTL values (check the `ttl` field in output), consider lowering them 24-48 hours before migration to reduce propagation time. Common approach:
- Lower TTLs to 300 seconds (5 minutes)
- Wait for old TTL to expire
- Then proceed with migration

### Step 3: Configure New Nameserver
Set up all records on your new nameserver. Use `pre_migration.json` as your reference to ensure nothing is missed.

### Step 4: Verify New Configuration
Before switching, query the new nameserver directly to confirm records are correct:

```bash
uv run dns_dump.py --csv domains.txt --compare --old-ns <current-ns-ip> --new-ns <new-ns-ip>
```

Review the comparison output:
- `dns_records_comparison.json` shows differences
- `old_only` - records missing from new NS (action required)
- `new_only` - new records added (verify intentional)

### Step 5: Update NS Records at Registrar
Once verified, update your domain's nameserver records at your registrar.

### Step 6: Monitor Propagation
Re-run the comparison periodically to monitor propagation:

```bash
uv run dns_dump.py example.com --compare --old-ns <old-ns-ip> --new-ns 8.8.8.8
```

Using a public resolver (8.8.8.8, 1.1.1.1) as `--new-ns` shows what the world sees.

### Step 7: Post-Migration Verification
After propagation (typically 24-48 hours), run a final dump:

```bash
uv run dns_dump.py --csv domains.txt --output post_migration
```

Compare `pre_migration.json` and `post_migration.json` to confirm all records migrated correctly.

---

## Requirements

- Python 3.11+
- [uv](https://docs.astral.sh/uv/) (recommended) or pip

## Usage

```bash
# Single domain
uv run dns_dump.py example.com

# Multiple domains from file (one domain per line)
uv run dns_dump.py --csv domains.txt

# Compare old vs new nameservers
uv run dns_dump.py example.com --compare --old-ns 8.8.8.8 --new-ns 1.1.1.1

# Custom output prefix
uv run dns_dump.py example.com --output my_dump
```

## Options

| Option | Description |
|--------|-------------|
| `domain` | Single domain to enumerate |
| `--csv FILE` | File with domains (one per line) |
| `--compare` | Enable comparison mode |
| `--old-ns IP` | Old nameserver IP (requires --compare) |
| `--new-ns IP` | New nameserver IP (requires --compare) |
| `--output PREFIX` | Output filename prefix (default: dns_records) |

## What It Checks

### Record Types
A, AAAA, CNAME, MX, TXT, NS, SOA, SRV, CAA, PTR

### Subdomains (44 total)
www, mail, email, webmail, smtp, pop, imap, ftp, api, dev, staging, test, beta, app, admin, portal, secure, vpn, remote, cdn, shop, store, blog, news, support, help, m, mobile, static, assets, img, images, ns1, ns2, dns, dns1, dns2, mx, mx1, mx2, mail1, mail2, autodiscover, autoconfig, cpanel, whm, webdisk

### Special Records (per subdomain)
- `_dmarc.{domain}` - DMARC policy
- `{selector}._domainkey.{domain}` - DKIM (15 common selectors)
- `_mta-sts.{domain}` - MTA-STS
- `default._bimi.{domain}` - BIMI
- `_443._tcp.{domain}` - TLSA/DANE

### Zone Transfer
Attempts AXFR on each domain's nameservers (usually blocked but worth trying).

## Output

### Standard Mode
- `dns_records.json` - Full results with TTL
- `dns_records.csv` - Same data in CSV format

### Comparison Mode
- `dns_records_comparison.json` - Diff summary (old_only, new_only counts)
- `dns_records_old.json` / `dns_records_old.csv` - Full dump from old NS
- `dns_records_new.json` / `dns_records_new.csv` - Full dump from new NS

## Example Output

```json
{
  "domain": "example.com",
  "type": "MX",
  "value": "10 mail.example.com.",
  "ttl": 3600
}
```

## Limitations

- Cannot discover arbitrary subdomains (only checks predefined list)
- DKIM selectors must be guessed (checks 15 common ones)
- Zone transfers usually blocked by nameservers
- No recursive subdomain enumeration
