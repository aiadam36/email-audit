from .dns_utils import get_txt_records


def check_dmarc(domain):
    records = get_txt_records(f"_dmarc.{domain}")

    for record in records:
        if record.startswith("v=DMARC1"):
            return True, record

    return False, None
