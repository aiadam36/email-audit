import dns.resolver

def get_txt_records(name):
    try:
        answers = dns.resolver.resolve(name, "TXT")
        return [
            "".join(
                part.decode() if isinstance(part, bytes) else part
                for part in record.strings
            )
            for record in answers
        ]
    except Exception:
        return []

def check_spf(domain):
    records = get_txt_records(domain)

    for record in records:
        if record.startswith("v=spf1"):
            return True, record

    return False, None

def check_dmarc(domain):
    records = get_txt_records(f"_dmarc.{domain}")

    for record in records:
        if record.startswith("v=DMARC1"):
            return True, record

    return False, None

def check_dkim(domain, selector):
    if not selector:
        return None, None

    records = get_txt_records(f"{selector}._domainkey.{domain}")

    for record in records:
        if "v=DKIM1" in record:
            return True, record

    return False, None

def print_result(name, status):
    print(f"{name:<10} {'PASS' if status else 'FAIL'}")

def main():
    print("Email Audit")
    print("=" * 40)

    domain = input("Domain: ").strip()

    selector = input(
        "DKIM selector (leave blank to skip DKIM): "
    ).strip()

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

    if spf_record:
        print(f"SPF:   {spf_record}")
    else:
        print("SPF:   Not found")

    print()

    if selector:
        if dkim_record:
            print(f"DKIM:  {dkim_record}")
        else:
            print("DKIM:  Not found")
        print()

    if dmarc_record:
        print(f"DMARC: {dmarc_record}")
    else:
        print("DMARC: Not found")

if __name__ == "__main__":
    main()
