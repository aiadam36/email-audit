from .dns_utils import get_txt_records


def check_tls_rpt(domain):
    records = get_txt_records(f"_smtp._tls.{domain}")

    for record in records:
        if record.startswith("v=TLSRPTv1"):
            return True, record

    return False, None
