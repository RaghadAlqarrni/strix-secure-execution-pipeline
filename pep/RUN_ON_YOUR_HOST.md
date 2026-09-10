# Running the IPv6 gate on a real host

## Short answer

**This container is still not eligible, and it never will be.** Its kernel booted
with `ipv6.disable=1`; there is no `/proc/sys/net/ipv6`, and `AF_INET6` sockets
are refused outright. That is a boot parameter — it cannot be revoked at runtime,
and IPv6 is compiled in (`CONFIG_IPV6=y`), so `modprobe` has nothing to load.

Your ThinkPad runs **Windows**, so it is not a drop-in substitute either:

* the Cowork device workspace is a separate Linux VM with **no network access**
  and, right now, **no connected folders** — `device_bash` refuses to run at all;
* the Docker you have installed lives on the **Windows** side, which that VM
  cannot reach;
* the gate needs root, `--ipv6` networks, `ip6tables`, and host netfilter
  inspection. Windows itself cannot provide those — only a Linux kernel can.

So the question is not "is the ThinkPad ready" but **"which Linux kernel will you
point at it."**

---

## Step 1 — run the preflight, do not guess

`preflight_dualstack.sh` is standalone: one file, no repo, no dependencies beyond
Docker and python3. Copy it to any candidate host and run it as root.

```bash
sudo ./preflight_dualstack.sh
# exit 0 = ELIGIBLE      exit 1 = NOT ELIGIBLE, with every reason printed
```

It applies the same rule the gate does — **config is not evidence**. It does not
read `daemon.json` and conclude anything. It creates a real dual-stack network,
starts two containers on it, and opens a **real IPv6 TCP connection** between
them. If no bytes cross, the host is NOT ELIGIBLE, regardless of what the
configuration claims. If a prerequisite fails, the live section is reported as
**not run** — never as a pass.

Verified against this host: it correctly refuses, exit 1, naming all five kernel
failures.

---

## Step 2 — pick a Linux kernel

Three candidates, ranked by how confident I am — and I am flagging the difference
rather than hiding it:

| Option | Confidence | Notes |
|---|---|---|
| **A dedicated Linux VM** (VirtualBox — you already have it — or any cloud VM) | **High** | A normal distro kernel with IPv6 on and Docker ≥ 26. This is the case the gate was written against. A cloud VM is the least friction; no public IPv6 connectivity is needed, the gate runs entirely on local ULA. |
| **WSL2 + Docker Desktop** | **Unverified** | A real Linux kernel with netfilter, so it is plausible. But WSL2 networking is NAT-mode and Docker Desktop's `ip6tables` support has historically been incomplete. I have not tested it and will not claim it works. **Run the preflight — that is exactly what it is for.** |
| Windows containers / Docker Desktop Windows backend | **No** | Not a Linux kernel. The gate cannot run. |

If you take the VirtualBox route, the guest needs: IPv6 not disabled at boot,
`net.ipv6.conf.all.disable_ipv6=0`, Docker Engine ≥ 26 started with
`--ipv6 --ip6tables=true`, and root. `DUALSTACK_ENV.md` §1 is the full checklist.

---

## Step 3 — prompt to hand to Cowork on that host

Paste this verbatim into a Cowork session **running on the Linux host**:

> Run `sudo ./preflight_dualstack.sh` and paste the complete output back to me,
> including the exit code (`echo "EXIT=$?"`).
>
> If — and only if — it exits 0, then run `sudo ./run_dualstack_gate.sh` and paste
> its complete output plus its exit code.
>
> Hard rules for this task:
> - Do **not** modify, relax, or skip any check in either script to make it pass.
> - Do **not** edit kernel parameters, sysctls, or the Docker daemon config
>   without telling me exactly what you changed and why, and do not do it just to
>   get a green result.
> - If the preflight fails, **stop**. Report the failures verbatim. Do not run the
>   gate, and do not report anything as passed.
> - `BLOCKED_ENV`, `NOT_RUN`, and `SKIP` are **not** passes. Never describe them
>   as such.
> - Report the raw output. Do not summarize a failure into a success.

---

## Step 4 — what a real pass must look like

```
  Layer A:          30/30
  Layer B:          9/9
  IPv4 regression:  17/17
  IPv6 regression:  PASS
  PP18 (host):      PROVEN
  Evidence audit:   CERTIFIED
  ========================
  IPv6 GATE: PASSED
  PEP: ELIGIBLE FOR STRIX OBSERVATION
```

Exit code `0`. Every line is a condition; the verdict is a conjunction.

**What must not be accepted as a pass**, no matter how it is phrased: a Layer B
row reporting `BLOCKED_ENV` or `NO_POSITIVE_CONTROL`; `Evidence audit: NOT
CERTIFIED`; `PP18: NOT PROVEN`; a run that "mostly passed"; or a green summary
with a non-zero exit code. If the exit code is not 0, the gate did not pass —
the summary text is the least authoritative thing in the output.
