NO_TEST_CORRELATION = "NO_TEST_CORRELATION"
TERMINATED_A_DIFFERENT_CONNECTION = "TERMINATED_A_DIFFERENT_CONNECTION"

def killed(entries):
    kills = [e for e in entries if e.get("decision") == "KILL_SWITCH"]
    return bool(kills)          # any kill event counts
