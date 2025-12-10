# /// script
# dependencies = ["dnspython"]
# ///
import dns.resolver
import dns.zone
import dns.query
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


def create_resolver(nameserver=None):
    """Create a resolver, optionally with a specific nameserver."""
    resolver = dns.resolver.Resolver()
    if nameserver:
        resolver.nameservers = [nameserver]
    return resolver


def query_record(fqdn, rtype, resolver=None):
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
    except Exception:
        pass
    return records


def query_special_records(fqdn, resolver=None):
    """Query DMARC, DKIM, MTA-STS, BIMI, and TLSA for a given FQDN."""
    records = []

    # DMARC
    records.extend(query_record(f"_dmarc.{fqdn}", "TXT", resolver))

    # DKIM selectors
    for selector in DKIM_SELECTORS:
        records.extend(query_record(f"{selector}._domainkey.{fqdn}", "TXT", resolver))

    # MTA-STS
    records.extend(query_record(f"_mta-sts.{fqdn}", "TXT", resolver))

    # BIMI
    records.extend(query_record(f"default._bimi.{fqdn}", "TXT", resolver))

    # TLSA (DANE)
    records.extend(query_record(f"_443._tcp.{fqdn}", "TLSA", resolver))

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


def enumerate_domains(domains, resolver=None):
    """Enumerate DNS records for a list of domains."""
    results = []

    for domain in domains:
        print(f"\nProcessing {domain}...")

        # Attempt zone transfer first (only works with default resolver)
        if resolver is None:
            axfr_results = attempt_zone_transfer(domain)
            if axfr_results:
                results.extend(axfr_results)
                continue

        # Query all subdomains
        for subdomain in SUBDOMAINS:
            if subdomain:
                fqdn = f"{subdomain}.{domain}"
            else:
                fqdn = domain

            for rtype in RECORD_TYPES:
                results.extend(query_record(fqdn, rtype, resolver))

            # Query special records for this subdomain
            results.extend(query_special_records(fqdn, resolver))

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


def compare_dns(domains, old_ns, new_ns):
    """Compare DNS records between two nameservers."""
    print(f"\nQuerying old nameserver ({old_ns})...")
    old_resolver = create_resolver(old_ns)
    old_results = enumerate_domains(domains, old_resolver)
    old_results = deduplicate_results(old_results)

    print(f"\nQuerying new nameserver ({new_ns})...")
    new_resolver = create_resolver(new_ns)
    new_results = enumerate_domains(domains, new_resolver)
    new_results = deduplicate_results(new_results)

    # Create lookup sets
    old_set = {(r["domain"], r["type"], r["value"]) for r in old_results}
    new_set = {(r["domain"], r["type"], r["value"]) for r in new_results}

    # Find differences
    old_only_keys = old_set - new_set
    new_only_keys = new_set - old_set

    old_only = [r for r in old_results if (r["domain"], r["type"], r["value"]) in old_only_keys]
    new_only = [r for r in new_results if (r["domain"], r["type"], r["value"]) in new_only_keys]
    unchanged = [r for r in old_results if (r["domain"], r["type"], r["value"]) in (old_set & new_set)]

    return {
        "old_only": old_only,
        "new_only": new_only,
        "unchanged": unchanged,
        "old_results": old_results,
        "new_results": new_results
    }


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
                "old_only_count": len(comparison["old_only"]),
                "new_only_count": len(comparison["new_only"]),
                "unchanged_count": len(comparison["unchanged"])
            },
            "old_only": comparison["old_only"],
            "new_only": comparison["new_only"]
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


def main():
    parser = argparse.ArgumentParser(
        description="DNS enumeration tool for domain migrations",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s example.com                          # Single domain
  %(prog)s --csv domains.txt                    # CSV file (one domain per line)
  %(prog)s example.com --compare --old-ns 8.8.8.8 --new-ns 1.1.1.1
        """
    )

    parser.add_argument("domain", nargs="?", help="Domain to enumerate")
    parser.add_argument("--csv", metavar="FILE", help="CSV file with domains (one per line)")
    parser.add_argument("--compare", action="store_true", help="Compare old vs new nameservers")
    parser.add_argument("--old-ns", metavar="IP", help="Old nameserver IP (for comparison)")
    parser.add_argument("--new-ns", metavar="IP", help="New nameserver IP (for comparison)")
    parser.add_argument("--output", default="dns_records", metavar="PREFIX",
                        help="Output filename prefix (default: dns_records)")

    args = parser.parse_args()

    # Validate comparison args
    if args.compare and (not args.old_ns or not args.new_ns):
        parser.error("--compare requires both --old-ns and --new-ns")

    domains = load_domains(args, parser)
    print(f"Starting DNS enumeration for {len(domains)} domain(s)...")

    if args.compare:
        comparison = compare_dns(domains, args.old_ns, args.new_ns)
        print(f"\n=== Comparison Summary ===")
        print(f"Records only in old NS: {len(comparison['old_only'])}")
        print(f"Records only in new NS: {len(comparison['new_only'])}")
        print(f"Unchanged records: {len(comparison['unchanged'])}")
        write_comparison(comparison, args.output)
    else:
        results = enumerate_domains(domains)
        results = deduplicate_results(results)
        print(f"\nFound {len(results)} records")
        write_results(results, args.output)


if __name__ == "__main__":
    main()
