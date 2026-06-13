import urllib.request
import urllib.error
import socket

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
        req = urllib.request.Request(url, headers={"User-Agent": "email-audit/1.0"})
        with urllib.request.urlopen(req, timeout=10) as response:
            body = response.read().decode().strip()
            return True, body

    except urllib.error.HTTPError as e:
        if e.code == 404:
            return False, "Policy file not found (HTTP 404)"
        if e.code == 403:
            return False, f"Access denied (HTTP 403) — check server permissions or Cloudflare rules"
        return False, f"HTTP error {e.code}"

    except urllib.error.URLError as e:
        reason = str(e.reason)
        if "Name or service not known" in reason or "nodename nor servname" in reason:
            return False, "mta-sts subdomain does not exist (DNS NXDOMAIN)"
        if "timed out" in reason.lower():
            return False, "Connection timed out"
        return False, f"Connection failed: {reason}"

    except socket.timeout:
        return False, "Connection timed out"

    except Exception as e:
        return False, f"Unexpected error: {e}"


def check_mta_sts(domain):
    dns_ok, dns_record = check_mta_sts_dns(domain)
    policy_ok, policy_body = check_mta_sts_policy(domain)

    return dns_ok, dns_record, policy_ok, policy_body
