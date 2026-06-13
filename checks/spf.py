from .dns_utils import get_txt_records


def check_spf(domain):
    records = get_txt_records(domain)

    for record in records:
        if record.startswith("v=spf1"):
            return True, record

    return False, None
