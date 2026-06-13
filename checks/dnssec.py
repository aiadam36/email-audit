import dns.resolver
import dns.rdatatype
import dns.flags


def check_dnssec(domain):
    """
    Checks for DNSSEC by querying for DNSKEY records at the zone apex
    and verifying the AD (Authenticated Data) flag is set in the response,
    which means the upstream resolver has validated the chain of trust.
    """
    try:
        # Query for DNSKEY — the resolver sets AD flag if validation passed
        resolver = dns.resolver.Resolver()
        resolver.use_edns(0, dns.flags.DO, 1232)  # Request DNSSEC records

        response = resolver.resolve(domain, "DNSKEY").response

        ad_flag = bool(response.flags & dns.flags.AD)
        dnskey_count = len(response.answer[0]) if response.answer else 0

        if ad_flag:
            return True, f"Validated — {dnskey_count} DNSKEY record(s) found, AD flag set"
        elif dnskey_count > 0:
            return False, f"{dnskey_count} DNSKEY record(s) found but AD flag not set (validation may not be enforced by resolver)"
        else:
            return False, "No DNSKEY records found"

    except dns.resolver.NoAnswer:
        return False, "No DNSKEY records found (DNSSEC not enabled)"
    except dns.resolver.NXDOMAIN:
        return False, "Domain does not exist"
    except Exception as e:
        return False, str(e)
