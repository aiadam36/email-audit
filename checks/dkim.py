from .dns_utils import get_txt_records


def check_dkim(domain, selector):
    if not selector:
        return None, None

    records = get_txt_records(f"{selector}._domainkey.{domain}")

    for record in records:
        if "v=DKIM1" in record:
            return True, record

    return False, None
