import dns.resolver


def check_mx(domain):
    try:
        answers = dns.resolver.resolve(domain, "MX")
        records = sorted(answers, key=lambda r: r.preference)
        entries = [(r.preference, str(r.exchange).rstrip(".")) for r in records]
        return True, entries
    except dns.resolver.NoAnswer:
        return False, "No MX records found"
    except dns.resolver.NXDOMAIN:
        return False, "Domain does not exist"
    except Exception as e:
        return False, str(e)
