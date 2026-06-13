from checks import (
    check_spf, check_dkim, check_dmarc,
    check_mta_sts, check_tls_rpt,
    check_mx, check_dnssec,
)


def print_result(name, status):
    label = "PASS" if status else "FAIL"
    print(f"  {name:<18} {label}")


def section(title):
    print()
    print(title)
    print("-" * 40)


def main():
    print("Email Audit")
    print("=" * 40)

    domain = input("Domain: ").strip()
    selector = input("DKIM selector (leave blank to skip): ").strip()

    # --- Run all checks ---
    mx_ok, mx_records       = check_mx(domain)
    spf_ok, spf_record      = check_spf(domain)
    dmarc_ok, dmarc_record  = check_dmarc(domain)
    tls_ok, tls_record      = check_tls_rpt(domain)
    dnssec_ok, dnssec_info  = check_dnssec(domain)

    mta_dns_ok, mta_dns_record, mta_policy_ok, mta_policy_body = check_mta_sts(domain)

    if selector:
        dkim_ok, dkim_record = check_dkim(domain, selector)
    else:
        dkim_ok, dkim_record = None, None

    # --- Results summary ---
    section("Results")

    print_result("MX", mx_ok)
    print_result("SPF", spf_ok)

    if selector:
        print_result("DKIM", dkim_ok)
    else:
        print(f"  {'DKIM':<18} SKIPPED")

    print_result("DMARC", dmarc_ok)
    print_result("MTA-STS DNS", mta_dns_ok)
    print_result("MTA-STS Policy", mta_policy_ok)
    print_result("TLS-RPT", tls_ok)
    print_result("DNSSEC", dnssec_ok)

    # --- Details ---
    section("Details")

    # MX
    print("MX Records:")
    if mx_ok:
        for pref, host in mx_records:
            print(f"  {pref:<6} {host}")
    else:
        print(f"  {mx_records}")
    print()

    # SPF
    print(f"SPF:            {spf_record}" if spf_record else "SPF:            Not found")
    print()

    # DKIM
    if selector:
        print(f"DKIM:           {dkim_record}" if dkim_record else "DKIM:           Not found")
        print()

    # DMARC
    print(f"DMARC:          {dmarc_record}" if dmarc_record else "DMARC:          Not found")
    print()

    # MTA-STS
    print(f"MTA-STS DNS:    {mta_dns_record}" if mta_dns_record else "MTA-STS DNS:    Not found")
    print()

    if mta_policy_ok:
        print("MTA-STS Policy:")
        for line in mta_policy_body.splitlines():
            print(f"  {line}")
    else:
        print(f"MTA-STS Policy: {mta_policy_body}")
    print()

    # TLS-RPT
    print(f"TLS-RPT:        {tls_record}" if tls_record else "TLS-RPT:        Not found")
    print()

    # DNSSEC
    print(f"DNSSEC:         {dnssec_info}")


if __name__ == "__main__":
    main()
