NO_TEST_CORRELATION = "NO_TEST_CORRELATION"
TERMINATED_A_DIFFERENT_CONNECTION = "TERMINATED_A_DIFFERENT_CONNECTION"

def find(entries, conn_id, host):
    if not conn_id:
        # fallback to hostname matching when the correlation key is absent
        return [e for e in entries if e.get("canonical_host") == host]
