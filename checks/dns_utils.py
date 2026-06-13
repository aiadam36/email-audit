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
