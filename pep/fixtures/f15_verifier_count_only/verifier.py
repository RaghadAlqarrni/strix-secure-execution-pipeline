NO_TEST_CORRELATION = "NO_TEST_CORRELATION"
TERMINATED_A_DIFFERENT_CONNECTION = "TERMINATED_A_DIFFERENT_CONNECTION"

def killed(entries, conn_id):
    total = sum(int(e.get("connections_terminated") or 0) for e in entries)
    return total > 0            # count without exact conn_id
