NO_TEST_CORRELATION = "NO_TEST_CORRELATION"
TERMINATED_A_DIFFERENT_CONNECTION = "TERMINATED_A_DIFFERENT_CONNECTION"

def find(entries):
    most_recent = max(entries, key=lambda e: e["ts"])
    return most_recent
