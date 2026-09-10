"""
Interception CA — dynamic leaf minting.

The proof harness pre-minted certificates for a fixed hostname list. Production
cannot: it must mint per destination on demand. Properties enforced here:

  * The CA private key is created with mode 0600 and never leaves this process's
    filesystem view. It is not mounted into any sandbox.
  * Leaf keys are likewise 0600 and live under a dedicated directory.
  * SANs are emitted correctly for BOTH families: ``DNS:`` for names,
    ``IP:`` for IPv4 *and* IPv6 literals.
  * Minting failure is an error, never a fallback to an unverified path — the
    caller must fail closed.
"""

from __future__ import annotations

import ipaddress
import os
import subprocess
import threading


class CAError(RuntimeError):
    pass


class InterceptionCA:
    def __init__(self, ca_dir: str, leaf_dir: str, cn: str = "Strix PEP Interception CA"):
        self.ca_dir = ca_dir
        self.leaf_dir = leaf_dir
        self.ca_key = os.path.join(ca_dir, "ca.key")
        self.ca_crt = os.path.join(ca_dir, "ca.crt")
        self.cn = cn
        self._lock = threading.Lock()
        self._cache: dict[str, tuple[str, str]] = {}
        os.makedirs(ca_dir, mode=0o700, exist_ok=True)
        os.makedirs(leaf_dir, mode=0o700, exist_ok=True)
        self._ensure_ca()

    # ------------------------------------------------------------------ CA root
    def _ensure_ca(self) -> None:
        if os.path.exists(self.ca_key) and os.path.exists(self.ca_crt):
            os.chmod(self.ca_key, 0o600)
            return
        r = subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:3072", "-nodes", "-days", "1825",
             "-keyout", self.ca_key, "-out", self.ca_crt, "-subj", f"/CN={self.cn}",
             "-addext", "basicConstraints=critical,CA:TRUE,pathlen:0",
             "-addext", "keyUsage=critical,keyCertSign,cRLSign"],
            capture_output=True, text=True)
        if r.returncode != 0:
            raise CAError(f"CA generation failed: {r.stderr[:200]}")
        os.chmod(self.ca_key, 0o600)
        os.chmod(self.ca_crt, 0o644)

    @property
    def ca_cert_path(self) -> str:
        """The PUBLIC certificate — the only artifact a sandbox ever receives."""
        return self.ca_crt

    # --------------------------------------------------------------- leaf certs
    @staticmethod
    def _san_for(host: str) -> str:
        try:
            ipaddress.ip_address(host)          # correct for v4 AND v6 literals
            return f"IP:{host}"
        except ValueError:
            return f"DNS:{host}"

    def leaf_for(self, host: str) -> tuple[str, str]:
        """Return (cert_path, key_path) for ``host``, minting on first use."""
        with self._lock:
            hit = self._cache.get(host)
            if hit:
                return hit

            safe = host.replace(":", "_").replace("/", "_")
            key = os.path.join(self.leaf_dir, f"{safe}.key")
            crt = os.path.join(self.leaf_dir, f"{safe}.crt")
            csr = os.path.join(self.leaf_dir, f"{safe}.csr")

            if not (os.path.exists(key) and os.path.exists(crt)):
                r = subprocess.run(
                    ["openssl", "req", "-newkey", "rsa:2048", "-nodes",
                     "-keyout", key, "-out", csr, "-subj", f"/CN={host}"],
                    capture_output=True, text=True)
                if r.returncode != 0:
                    raise CAError(f"leaf key/csr failed for {host}: {r.stderr[:200]}")

                ext = os.path.join(self.leaf_dir, f"{safe}.ext")
                with open(ext, "w") as fh:
                    fh.write(f"subjectAltName={self._san_for(host)}\n"
                             "extendedKeyUsage=serverAuth\n"
                             "basicConstraints=critical,CA:FALSE\n")
                r = subprocess.run(
                    ["openssl", "x509", "-req", "-in", csr, "-CA", self.ca_crt,
                     "-CAkey", self.ca_key, "-CAcreateserial", "-days", "397",
                     "-out", crt, "-extfile", ext],
                    capture_output=True, text=True)
                for tmp in (csr, ext):
                    try:
                        os.unlink(tmp)
                    except OSError:
                        pass
                if r.returncode != 0:
                    raise CAError(f"leaf signing failed for {host}: {r.stderr[:200]}")
                os.chmod(key, 0o600)
                os.chmod(crt, 0o644)

            self._cache[host] = (crt, key)
            return crt, key
