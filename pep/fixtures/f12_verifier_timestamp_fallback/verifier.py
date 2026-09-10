NO_TEST_CORRELATION = "NO_TEST_CORRELATION"
TERMINATED_A_DIFFERENT_CONNECTION = "TERMINATED_A_DIFFERENT_CONNECTION"

def find(entries, conn_id):
    if not conn_id:
        return sorted(entries, key=lambda e: e["ts"])[-1]
