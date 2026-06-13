from checks import check_spf, check_dkim, check_dmarc


def print_result(name, status):
    print(f"{name:<10} {'PASS' if status else 'FAIL'}")


def main():
    print("Email Audit")
    print("=" * 40)

    domain = input("Domain: ").strip()
    selector = input("DKIM selector (leave blank to skip DKIM): ").strip()

    print()

    spf_ok, spf_record = check_spf(domain)
    dmarc_ok, dmarc_record = check_dmarc(domain)

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
        print(f"{'DKIM':<10} SKIPPED")

    print_result("DMARC", dmarc_ok)

    print()
    print("Details")
    print("-" * 40)

    print(f"SPF:   {spf_record}" if spf_record else "SPF:   Not found")
    print()

    if selector:
        print(f"DKIM:  {dkim_record}" if dkim_record else "DKIM:  Not found")
        print()

    print(f"DMARC: {dmarc_record}" if dmarc_record else "DMARC: Not found")


if __name__ == "__main__":
    main()
