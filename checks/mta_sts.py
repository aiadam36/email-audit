import urllib.request
import urllib.error

from .dns_utils import get_txt_records


def check_mta_sts_dns(domain):
    records = get_txt_records(f"_mta-sts.{domain}")

    for record in records:
        if record.startswith("v=STSv1"):
            return True, record

    return False, None


def check_mta_sts_policy(domain):
    url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"

    try:
        with urllib.request.urlopen(url, timeout=5) as response:
            body = response.read().decode().strip()
            return True, body
    except urllib.error.HTTPError as e:
        return False, f"HTTP {e.code}"
    except Exception as e:
        return False, str(e)


def check_mta_sts(domain):
    dns_ok, dns_record = check_mta_sts_dns(domain)
    policy_ok, policy_body = check_mta_sts_policy(domain)

    return dns_ok, dns_record, policy_ok, policy_body
