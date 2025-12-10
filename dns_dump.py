# /// script
# dependencies = ["dnspython"]
# ///
import dns.resolver
import dns.zone
import dns.query
import dns.exception
import json
import csv
import argparse

# Common subdomains to check
SUBDOMAINS = [
    "", "www", "mail", "email", "webmail", "smtp", "pop", "imap",
    "ftp", "api", "dev", "staging", "test", "beta", "app",
    "admin", "portal", "secure", "vpn", "remote", "cdn",
    "shop", "store", "blog", "news", "support", "help",
    "m", "mobile", "static", "assets", "img", "images",
    "ns1", "ns2", "dns", "dns1", "dns2",
    "mx", "mx1", "mx2", "mail1", "mail2",
    "autodiscover", "autoconfig", "cpanel", "whm", "webdisk"
]

# Common DKIM selectors
DKIM_SELECTORS = [
    "google", "selector1", "selector2", "default", "k1", "k2",
    "dkim", "mail", "email", "s1", "s2", "sm1", "sm2",
    "mandrill", "mailchimp", "sendgrid", "amazonses", "postmark"
]

RECORD_TYPES = ["A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA", "SRV", "CAA", "PTR"]

# DNSSEC record types (queried at root domain only)
DNSSEC_TYPES = ["DS", "DNSKEY"]

# Record types for wildcard queries
WILDCARD_TYPES = ["A", "AAAA", "CNAME"]

# Global error tracking
query_errors = []


def create_resolver(nameserver=None):
    """Create a resolver, optionally with a specific nameserver."""
    resolver = dns.resolver.Resolver()
    if nameserver:
        resolver.nameservers = [nameserver]
    return resolver


def query_record(fqdn, rtype, resolver=None, verbose=False):
    """Query a DNS record and return results."""
    if resolver is None:
        resolver = create_resolver()
    records = []
    try:
        answers = resolver.resolve(fqdn, rtype)
        for ans in answers:
            records.append({
                "domain": fqdn,
                "type": rtype,
                "value": ans.to_text(),
                "ttl": answers.ttl
            })
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        # Normal - record doesn't exist, no answer, or no nameservers for this zone
        pass
    except dns.exception.Timeout:
        if verbose:
            print(f"  [WARN] {fqdn} {rtype}: Query timeout")
        query_errors.append({"fqdn": fqdn, "type": rtype, "error": "Timeout"})
    except Exception as e:
        if verbose:
            print(f"  [WARN] {fqdn} {rtype}: {type(e).__name__}")
        query_errors.append({"fqdn": fqdn, "type": rtype, "error": type(e).__name__})
    return records


def query_special_records(fqdn, resolver=None, verbose=False):
    """Query DMARC, DKIM, MTA-STS, BIMI, and TLSA for a given FQDN."""
    records = []

    # DMARC
    records.extend(query_record(f"_dmarc.{fqdn}", "TXT", resolver, verbose))

    # DKIM selectors
    for selector in DKIM_SELECTORS:
        records.extend(query_record(f"{selector}._domainkey.{fqdn}", "TXT", resolver, verbose))

    # MTA-STS
    records.extend(query_record(f"_mta-sts.{fqdn}", "TXT", resolver, verbose))

    # BIMI
    records.extend(query_record(f"default._bimi.{fqdn}", "TXT", resolver, verbose))

    # TLSA (DANE)
    records.extend(query_record(f"_443._tcp.{fqdn}", "TLSA", resolver, verbose))

    return records


def query_wildcard(domain, resolver=None, verbose=False):
    """Query wildcard records for a domain."""
    records = []
    fqdn = f"*.{domain}"
    for rtype in WILDCARD_TYPES:
        results = query_record(fqdn, rtype, resolver, verbose)
        for r in results:
            r["is_wildcard"] = True
        records.extend(results)
    return records


def query_dnssec(domain, resolver=None, verbose=False):
    """Query DNSSEC records for root domain only."""
    records = []
    for rtype in DNSSEC_TYPES:
        results = query_record(domain, rtype, resolver, verbose)
        for r in results:
            r["is_dnssec"] = True
        records.extend(results)
    return records


def attempt_zone_transfer(domain):
    """Attempt AXFR zone transfer (usually blocked but worth trying)."""
    records = []
    try:
        ns_answers = dns.resolver.resolve(domain, "NS")
        for ns in ns_answers:
            ns_host = str(ns).rstrip(".")
            try:
                zone = dns.zone.from_xfr(dns.query.xfr(ns_host, domain, lifetime=5))
                for name, node in zone.nodes.items():
                    for rdataset in node.rdatasets:
                        for rdata in rdataset:
                            fqdn = f"{name}.{domain}" if str(name) != "@" else domain
                            records.append({
                                "domain": fqdn,
                                "type": dns.rdatatype.to_text(rdataset.rdtype),
                                "value": rdata.to_text(),
                                "ttl": rdataset.ttl,
                                "source": "AXFR"
                            })
                print(f"  [!] Zone transfer succeeded for {domain} via {ns_host}")
                break
            except Exception:
                pass
    except Exception:
        pass
    return records


def enumerate_domains(domains, resolver=None, verbose=False, extra_subdomains=None):
    """Enumerate DNS records for a list of domains."""
    results = []

    # Combine default and custom subdomains, deduplicate while preserving order
    all_subdomains = SUBDOMAINS.copy()
    if extra_subdomains:
        all_subdomains.extend(extra_subdomains)
    all_subdomains = list(dict.fromkeys(all_subdomains))

    for domain in domains:
        print(f"\nProcessing {domain}...")

        # Attempt zone transfer first (only works with default resolver)
        if resolver is None:
            axfr_results = attempt_zone_transfer(domain)
            if axfr_results:
                results.extend(axfr_results)
                continue

        # Query DNSSEC records for root domain
        results.extend(query_dnssec(domain, resolver, verbose))

        # Query wildcard records
        results.extend(query_wildcard(domain, resolver, verbose))

        # Query all subdomains
        for subdomain in all_subdomains:
            if subdomain:
                fqdn = f"{subdomain}.{domain}"
            else:
                fqdn = domain

            for rtype in RECORD_TYPES:
                results.extend(query_record(fqdn, rtype, resolver, verbose))

            # Query special records for this subdomain
            results.extend(query_special_records(fqdn, resolver, verbose))

    return results


def deduplicate_results(results):
    """Remove duplicate records."""
    seen = set()
    unique_results = []
    for r in results:
        key = (r["domain"], r["type"], r["value"])
        if key not in seen:
            seen.add(key)
            unique_results.append(r)
    return unique_results


def detect_changes(old_results, new_results):
    """Detect changed records between old and new results.

    Groups records by (domain, type) to identify:
    - old_only: Records truly removed (domain+type not in new)
    - new_only: Records truly added (domain+type not in old)
    - changed: Same domain+type but different values
    - unchanged: Same domain+type+value
    """
    def build_lookup(results):
        lookup = {}
        for r in results:
            key = (r["domain"], r["type"])
            if key not in lookup:
                lookup[key] = []
            lookup[key].append({"value": r["value"], "ttl": r["ttl"]})
        return lookup

    old_lookup = build_lookup(old_results)
    new_lookup = build_lookup(new_results)

    old_keys = set(old_lookup.keys())
    new_keys = set(new_lookup.keys())

    # Keys only in old (truly removed)
    removed_keys = old_keys - new_keys
    # Keys only in new (truly added)
    added_keys = new_keys - old_keys
    # Keys in both (could be unchanged or changed)
    common_keys = old_keys & new_keys

    changed = []
    unchanged = []

    for key in common_keys:
        old_values = set(v["value"] for v in old_lookup[key])
        new_values = set(v["value"] for v in new_lookup[key])

        if old_values == new_values:
            # Truly unchanged
            for r in old_results:
                if (r["domain"], r["type"]) == key:
                    unchanged.append(r)
        else:
            # Changed - values differ
            changed.append({
                "domain": key[0],
                "type": key[1],
                "old_values": old_lookup[key],
                "new_values": new_lookup[key]
            })

    # Build old_only from truly removed keys
    old_only = [r for r in old_results if (r["domain"], r["type"]) in removed_keys]
    # Build new_only from truly added keys
    new_only = [r for r in new_results if (r["domain"], r["type"]) in added_keys]

    return {
        "old_only": old_only,
        "new_only": new_only,
        "unchanged": unchanged,
        "changed": changed
    }


def compare_dns(domains, old_ns, new_ns, verbose=False, extra_subdomains=None):
    """Compare DNS records between two nameservers."""
    print(f"\nQuerying old nameserver ({old_ns})...")
    old_resolver = create_resolver(old_ns)
    old_results = enumerate_domains(domains, old_resolver, verbose, extra_subdomains)
    old_results = deduplicate_results(old_results)

    print(f"\nQuerying new nameserver ({new_ns})...")
    new_resolver = create_resolver(new_ns)
    new_results = enumerate_domains(domains, new_resolver, verbose, extra_subdomains)
    new_results = deduplicate_results(new_results)

    comparison = detect_changes(old_results, new_results)
    comparison["old_results"] = old_results
    comparison["new_results"] = new_results
    return comparison


def write_results(results, output_prefix):
    """Write results to JSON and CSV files."""
    json_file = f"{output_prefix}.json"
    csv_file = f"{output_prefix}.csv"

    with open(json_file, "w") as jf:
        json.dump(results, jf, indent=2)

    with open(csv_file, "w", newline="") as cf:
        fieldnames = ["domain", "type", "value", "ttl"]
        if any("source" in r for r in results):
            fieldnames.append("source")
        writer = csv.DictWriter(cf, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(results)

    print(f"Created {json_file} and {csv_file}")


def write_comparison(comparison, output_prefix):
    """Write comparison results to files."""
    # Full comparison JSON
    comparison_file = f"{output_prefix}_comparison.json"
    with open(comparison_file, "w") as f:
        json.dump({
            "summary": {
                "removed_count": len(comparison["old_only"]),
                "added_count": len(comparison["new_only"]),
                "changed_count": len(comparison["changed"]),
                "unchanged_count": len(comparison["unchanged"])
            },
            "removed": comparison["old_only"],
            "added": comparison["new_only"],
            "changed": comparison["changed"]
        }, f, indent=2)
    print(f"Created {comparison_file}")

    # Also write full dumps for each nameserver
    write_results(comparison["old_results"], f"{output_prefix}_old")
    write_results(comparison["new_results"], f"{output_prefix}_new")


def load_domains(args, parser):
    """Load domains from CLI argument or CSV file."""
    if args.csv:
        with open(args.csv) as f:
            domains = [line.strip() for line in f if line.strip()]
        if not domains:
            parser.error(f"No domains found in {args.csv}")
        return domains
    elif args.domain:
        return [args.domain]
    else:
        parser.error("Provide a domain or --csv file")


def load_custom_subdomains(args):
    """Load custom subdomains from CLI args and/or file."""
    custom = []
    if args.subdomains:
        custom.extend([s.strip() for s in args.subdomains.split(",") if s.strip()])
    if args.subdomain_file:
        with open(args.subdomain_file) as f:
            custom.extend([line.strip() for line in f if line.strip() and not line.startswith("#")])
    return custom


def print_error_summary(verbose):
    """Print summary of query errors."""
    if query_errors:
        print(f"\n[!] {len(query_errors)} queries encountered errors")
        if verbose:
            for err in query_errors:
                print(f"    {err['fqdn']} {err['type']}: {err['error']}")


def main():
    global query_errors
    query_errors = []  # Reset for each run

    parser = argparse.ArgumentParser(
        description="DNS enumeration tool for domain migrations",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s example.com                          # Single domain
  %(prog)s --csv domains.txt                    # CSV file (one domain per line)
  %(prog)s example.com --compare --old-ns 8.8.8.8 --new-ns 1.1.1.1
  %(prog)s example.com --subdomains git,gitlab  # Add custom subdomains
  %(prog)s example.com -v                       # Verbose mode (show warnings)
        """
    )

    parser.add_argument("domain", nargs="?", help="Domain to enumerate")
    parser.add_argument("--csv", metavar="FILE", help="CSV file with domains (one per line)")
    parser.add_argument("--compare", action="store_true", help="Compare old vs new nameservers")
    parser.add_argument("--old-ns", metavar="IP", help="Old nameserver IP (for comparison)")
    parser.add_argument("--new-ns", metavar="IP", help="New nameserver IP (for comparison)")
    parser.add_argument("--output", default="dns_records", metavar="PREFIX",
                        help="Output filename prefix (default: dns_records)")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Show warnings for failed queries")
    parser.add_argument("--subdomains", metavar="LIST",
                        help="Additional subdomains (comma-separated, e.g., git,gitlab)")
    parser.add_argument("--subdomain-file", metavar="FILE",
                        help="File with additional subdomains (one per line)")

    args = parser.parse_args()

    # Validate comparison args
    if args.compare and (not args.old_ns or not args.new_ns):
        parser.error("--compare requires both --old-ns and --new-ns")

    domains = load_domains(args, parser)
    custom_subs = load_custom_subdomains(args)

    if custom_subs:
        print(f"Adding {len(custom_subs)} custom subdomain(s)")

    print(f"Starting DNS enumeration for {len(domains)} domain(s)...")

    if args.compare:
        comparison = compare_dns(domains, args.old_ns, args.new_ns, args.verbose, custom_subs)
        print(f"\n=== Comparison Summary ===")
        print(f"Removed (old only): {len(comparison['old_only'])}")
        print(f"Added (new only): {len(comparison['new_only'])}")
        print(f"Changed: {len(comparison['changed'])}")
        print(f"Unchanged: {len(comparison['unchanged'])}")

        if comparison['changed']:
            print(f"\n=== Changed Records ===")
            for c in comparison['changed']:
                old_vals = ", ".join(v["value"] for v in c["old_values"])
                new_vals = ", ".join(v["value"] for v in c["new_values"])
                print(f"  {c['domain']} {c['type']}: {old_vals} -> {new_vals}")

        write_comparison(comparison, args.output)
    else:
        results = enumerate_domains(domains, verbose=args.verbose, extra_subdomains=custom_subs)
        results = deduplicate_results(results)
        print(f"\nFound {len(results)} records")
        write_results(results, args.output)

    print_error_summary(args.verbose)


if __name__ == "__main__":
    main()
