import dns.resolver
import dns.rdatatype
import dns.flags


# Use Cloudflare's validating resolver explicitly — system resolvers (local/ISP)
# often don't set the AD flag even for fully valid DNSSEC chains.
VALIDATING_RESOLVERS = ["1.1.1.1", "8.8.8.8"]


def check_dnssec(domain):
    """
    Checks DNSSEC by querying a known validating resolver (Cloudflare 1.1.1.1)
    for DNSKEY records with the DO flag set, then checks the AD (Authenticated Data)
    flag in the response — set only when the full chain of trust is verified.
    """
    resolver = dns.resolver.Resolver()
    resolver.nameservers = VALIDATING_RESOLVERS
    resolver.use_edns(0, dns.flags.DO, 1232)

    try:
        response = resolver.resolve(domain, "DNSKEY").response

        ad_flag = bool(response.flags & dns.flags.AD)
        dnskey_count = sum(len(rrset) for rrset in response.answer) if response.answer else 0

        if ad_flag:
            return True, f"Validated — {dnskey_count} DNSKEY record(s), AD flag set (chain of trust verified)"
        elif dnskey_count > 0:
            return False, f"{dnskey_count} DNSKEY record(s) found but chain of trust could not be verified"
        else:
            return False, "No DNSKEY records found (DNSSEC not enabled)"

    except dns.resolver.NoAnswer:
        return False, "No DNSKEY records found (DNSSEC not enabled)"
    except dns.resolver.NXDOMAIN:
        return False, "Domain does not exist"
    except Exception as e:
        return False, f"Lookup error: {e}"
