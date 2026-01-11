from threatwatch.auth_log_analyzer import LogParser

def test_parser_parses_at_least_one_entry_from_sample_data():
    parser = LogParser()
    with open("sample_data/auth.log", "r", encoding="utf-8") as f:
        lines = [ln.rstrip("\n") for ln in f]

    entries = []
    for ln in lines:
        entry = parser.parse_line(ln)
        if entry is not None:
            entries.append(entry)

    assert len(entries) >= 1
