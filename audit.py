from checks import check_spf, check_dkim, check_dmarc, check_mta_sts, check_tls_rpt


def print_result(name, status):
    print(f"{name:<12} {'PASS' if status else 'FAIL'}")


def main():
    print("Email Audit")
    print("=" * 40)

    domain = input("Domain: ").strip()
    selector = input("DKIM selector (leave blank to skip DKIM): ").strip()

    print()

    spf_ok, spf_record = check_spf(domain)
    dmarc_ok, dmarc_record = check_dmarc(domain)
    mta_dns_ok, mta_dns_record, mta_policy_ok, mta_policy_body = check_mta_sts(domain)
    tls_rpt_ok, tls_rpt_record = check_tls_rpt(domain)

    if selector:
        dkim_ok, dkim_record = check_dkim(domain, selector)
    else:
        dkim_ok = None
        dkim_record = None

    print("Results")
    print("-" * 40)

    print_result("SPF", spf_ok)

    if selector:
        print_result("DKIM", dkim_ok)
    else:
        print(f"{'DKIM':<12} SKIPPED")

    print_result("DMARC", dmarc_ok)
    print_result("MTA-STS DNS", mta_dns_ok)
    print_result("MTA-STS Policy", mta_policy_ok)
    print_result("TLS-RPT", tls_rpt_ok)

    print()
    print("Details")
    print("-" * 40)

    print(f"SPF:            {spf_record}" if spf_record else "SPF:            Not found")
    print()

    if selector:
        print(f"DKIM:           {dkim_record}" if dkim_record else "DKIM:           Not found")
        print()

    print(f"DMARC:          {dmarc_record}" if dmarc_record else "DMARC:          Not found")
    print()

    print(f"MTA-STS DNS:    {mta_dns_record}" if mta_dns_record else "MTA-STS DNS:    Not found")
    print()

    if mta_policy_ok:
        print("MTA-STS Policy:")
        for line in mta_policy_body.splitlines():
            print(f"  {line}")
    else:
        print(f"MTA-STS Policy: {mta_policy_body}")
    print()

    print(f"TLS-RPT:        {tls_rpt_record}" if tls_rpt_record else "TLS-RPT:        Not found")


if __name__ == "__main__":
    main()
