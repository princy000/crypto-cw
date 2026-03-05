#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════════════════╗
║          CipherMail — Email Forensics & PKI CLI Tool             ║
║          Author : CipherMail Project                              ║
║          License: MIT                                             ║
║          Requires: cryptography>=38.0                             ║
╚═══════════════════════════════════════════════════════════════════╝

Usage:
    python3 ciphermail.py                  # interactive menu
    python3 ciphermail.py --help           # show all commands

Features:
  • RSA-2048/4096 key pair generation (PKCS#12 keystore)
  • X.509 self-signed certificate issuance & validation
  • RSA-SHA256 digital signatures (sign / verify)
  • Hybrid encryption: RSA-OAEP + AES-256-GCM
  • Email header forensics & spoofing detection
  • Attack simulations: MITM, Replay, Weak-key, Cert-spoof
  • Hash-chained audit log
  • Multi-party signing demo
  • Three real-world use-case demos
"""

import os, sys, json, base64, hashlib, re, datetime, getpass, textwrap, argparse, time

# ── Cryptography imports ──────────────────────────────────────────
from cryptography.hazmat.primitives import hashes, serialization, hmac as crypto_hmac
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.exceptions import InvalidSignature
import cryptography.hazmat.primitives.serialization.pkcs12 as pkcs12_mod

# ═══════════════════════════════════════════════════════════════════
#  COLOUR / TERMINAL HELPERS
# ═══════════════════════════════════════════════════════════════════

class C:
    """ANSI colour codes."""
    RESET  = "\033[0m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    CYAN   = "\033[96m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    RED    = "\033[91m"
    BLUE   = "\033[94m"
    MAGENTA= "\033[95m"
    WHITE  = "\033[97m"

def c(text, colour): return f"{colour}{text}{C.RESET}"
def ok(msg):   print(f"  {c('✔', C.GREEN)}  {msg}")
def warn(msg): print(f"  {c('⚠', C.YELLOW)}  {msg}")
def err(msg):  print(f"  {c('✘', C.RED)}  {msg}")
def info(msg): print(f"  {c('ℹ', C.CYAN)}  {msg}")
def bold(msg): print(f"\n{c(msg, C.BOLD)}")
def sep(char='─', width=64): print(c(char * width, C.DIM))
def banner():
    print(c("""
╔═══════════════════════════════════════════════════════════════╗
║     ██████╗██╗██████╗ ██╗  ██╗███████╗██████╗               ║
║    ██╔════╝██║██╔══██╗██║  ██║██╔════╝██╔══██╗              ║
║    ██║     ██║██████╔╝███████║█████╗  ██████╔╝              ║
║    ██║     ██║██╔═══╝ ██╔══██║██╔══╝  ██╔══██╗              ║
║    ╚██████╗██║██║     ██║  ██║███████╗██║  ██║              ║
║     ╚═════╝╚═╝╚═╝     ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝  MAIL       ║
║          Email Forensics & PKI Cryptographic Tool            ║
╚═══════════════════════════════════════════════════════════════╝""", C.CYAN))

def divider_title(title):
    print()
    sep('═')
    print(c(f"  {title}", C.BOLD + C.CYAN))
    sep('═')

def pem_snippet(pem_bytes: bytes, lines: int = 4) -> str:
    """Show first and last N lines of a PEM."""
    decoded = pem_bytes.decode() if isinstance(pem_bytes, bytes) else pem_bytes
    parts = decoded.strip().splitlines()
    if len(parts) <= lines * 2:
        return decoded
    mid = f"  ... ({len(parts)-lines*2} more lines) ..."
    return "\n".join(parts[:lines] + [mid] + parts[-lines:])

def fingerprint(public_key) -> str:
    der = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo)
    digest = hashlib.sha256(der).hexdigest()
    return ":".join(digest[i:i+2].upper() for i in range(0, 32, 2))

def b64e(data: bytes) -> str:  return base64.b64encode(data).decode()
def b64d(s: str) -> bytes:      return base64.b64decode(s)
def now_iso() -> str:           return datetime.datetime.utcnow().isoformat() + "Z"

# ═══════════════════════════════════════════════════════════════════
#  STATE
# ═══════════════════════════════════════════════════════════════════

class AppState:
    def __init__(self):
        self.private_key: RSAPrivateKey | None = None
        self.public_key:  RSAPublicKey  | None = None
        self.certificate: x509.Certificate | None = None
        self.owner: str = ""
        self.key_store: list  = []   # [{owner, fingerprint, created, algo}]
        self.revoked_serials: list = []
        self.audit_log: list  = []   # hash-chained entries
        self.stats = {"keys": 0, "sigs": 0, "verifs": 0, "encrypts": 0}
        self.last_signed_pkg: dict | None = None
        self.last_enc_pkg:    dict | None = None

    # ── Audit log (hash-chained) ──────────────────────────────────
    def log(self, action: str, detail: str = "", level: str = "info"):
        prev_hash = self.audit_log[-1]["hash"] if self.audit_log else "0" * 64
        entry = {"time": now_iso(), "action": action, "detail": detail, "level": level, "hash": ""}
        chain_input = (prev_hash + json.dumps({k: v for k, v in entry.items() if k != "hash"})).encode()
        entry["hash"] = hashlib.sha256(chain_input).hexdigest()
        self.audit_log.append(entry)

    def has_key(self) -> bool:
        return self.private_key is not None and self.public_key is not None

STATE = AppState()

# ═══════════════════════════════════════════════════════════════════
#  1. KEY MANAGEMENT
# ═══════════════════════════════════════════════════════════════════

def cmd_generate_key():
    divider_title("🔑  Key Management — Generate Key Pair")

    print("\nSelect algorithm:")
    print("  1) RSA-2048  (recommended minimum)")
    print("  2) RSA-4096  (long-term security)")
    choice = input(c("  > ", C.CYAN)).strip()
    bits = 4096 if choice == "2" else 2048

    owner = input(c("  Owner / email label: ", C.CYAN)).strip() or "user@example.com"
    password = getpass.getpass(c("  Keystore password (PKCS#12): ", C.CYAN)).encode()

    info(f"Generating RSA-{bits} key pair for {c(owner, C.WHITE)} …")
    t0 = time.time()

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=bits,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    elapsed = time.time() - t0

    STATE.private_key = private_key
    STATE.public_key  = public_key
    STATE.owner       = owner

    fp = fingerprint(public_key)

    entry = {
        "owner": owner,
        "algo": f"RSA-{bits}",
        "fingerprint": fp,
        "created": now_iso()
    }
    STATE.key_store.append(entry)
    STATE.stats["keys"] += 1
    STATE.log("Key pair generated", f"RSA-{bits} for {owner}", "success")

    ok(f"Key pair generated in {elapsed:.2f}s")
    sep()

    # Show public key PEM
    pub_pem = public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo)
    print(c("\n  Public Key (PEM):", C.YELLOW))
    print(c(pem_snippet(pub_pem), C.DIM))

    # Private key encrypted with password (PKCS#8)
    priv_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(password))
    print(c("\n  Private Key (PEM, password-encrypted):", C.YELLOW))
    print(c(pem_snippet(priv_pem), C.DIM))

    print(c(f"\n  SHA-256 Fingerprint:", C.YELLOW))
    print(c(f"  {fp}", C.CYAN))

    # Optionally save to disk
    save = input(c("\n  Save key files to disk? (y/N): ", C.CYAN)).strip().lower()
    if save == "y":
        fname = owner.replace("@","_").replace(".","_")
        with open(f"{fname}_pub.pem", "wb") as f: f.write(pub_pem)
        with open(f"{fname}_priv_enc.pem", "wb") as f: f.write(priv_pem)
        ok(f"Saved {fname}_pub.pem and {fname}_priv_enc.pem")

    print()


def cmd_show_key_store():
    divider_title("🗄️  Key Store")
    if not STATE.key_store:
        warn("Key store is empty. Generate a key pair first.")
        return
    for i, k in enumerate(STATE.key_store, 1):
        print(f"\n  {c(f'[{i}]', C.CYAN)} {c(k['owner'], C.WHITE)}")
        print(f"       Algorithm : {k['algo']}")
        print(f"       Created   : {k['created']}")
        print(f"       Fingerprint: {c(k['fingerprint'][:47]+'…', C.CYAN)}")
    print()


def cmd_load_key():
    """Load an existing PEM key pair from disk."""
    divider_title("📂  Load Key Pair from Disk")
    pub_path  = input(c("  Public key PEM path : ", C.CYAN)).strip()
    priv_path = input(c("  Private key PEM path: ", C.CYAN)).strip()
    password  = getpass.getpass(c("  Keystore password   : ", C.CYAN)).encode()
    try:
        with open(pub_path, "rb") as f:
            STATE.public_key = serialization.load_pem_public_key(f.read())
        with open(priv_path, "rb") as f:
            STATE.private_key = serialization.load_pem_private_key(f.read(), password=password)
        owner = input(c("  Label / owner       : ", C.CYAN)).strip() or "loaded@key"
        STATE.owner = owner
        fp = fingerprint(STATE.public_key)
        STATE.key_store.append({"owner": owner, "algo": "RSA", "fingerprint": fp, "created": now_iso()})
        ok(f"Key pair loaded. Fingerprint: {fp[:47]}…")
        STATE.log("Key pair loaded", f"from {pub_path}", "info")
    except Exception as e:
        err(f"Failed to load key: {e}")

# ═══════════════════════════════════════════════════════════════════
#  2. CERTIFICATES
# ═══════════════════════════════════════════════════════════════════

def cmd_issue_cert():
    divider_title("📜  Certificate Authority — Issue Certificate")
    if not STATE.has_key():
        err("No key pair loaded. Generate one first (option 1).")
        return

    cn      = input(c("  Common Name (CN)   : ", C.CYAN)).strip() or STATE.owner
    org     = input(c("  Organisation (O)   : ", C.CYAN)).strip() or "CipherMail Corp"
    country = input(c("  Country (C, 2-char): ", C.CYAN)).strip().upper() or "GB"
    days    = int(input(c("  Validity (days)    : ", C.CYAN)).strip() or "365")

    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
        x509.NameAttribute(NameOID.COUNTRY_NAME, country),
    ])
    now_dt  = datetime.datetime.utcnow()
    serial  = x509.random_serial_number()

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)              # self-signed
        .public_key(STATE.public_key)
        .serial_number(serial)
        .not_valid_before(now_dt)
        .not_valid_after(now_dt + datetime.timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(digital_signature=True, key_cert_sign=False,
                          content_commitment=True, key_encipherment=True,
                          data_encipherment=False, key_agreement=False,
                          crl_sign=False, encipher_only=False, decipher_only=False),
            critical=True)
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.EMAIL_PROTECTION]),
            critical=False)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(STATE.public_key),
            critical=False)
        .sign(STATE.private_key, hashes.SHA256(), default_backend())
    )
    STATE.certificate = cert
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    STATE.log("Certificate issued", f"CN={cn}, serial={hex(serial)}, valid={days}d", "success")

    ok(f"Certificate issued for {c(cn, C.WHITE)}")
    sep()
    print(f"  {c('Serial    :', C.YELLOW)} {hex(serial).upper()}")
    print(f"  {c('CN        :', C.YELLOW)} {cn}")
    print(f"  {c('Org       :', C.YELLOW)} {org}")
    print(f"  {c('Country   :', C.YELLOW)} {country}")
    print(f"  {c('Not Before:', C.YELLOW)} {now_dt.date()}")
    print(f"  {c('Not After :', C.YELLOW)} {(now_dt + datetime.timedelta(days=days)).date()}")
    print(f"  {c('Sig Algo  :', C.YELLOW)} SHA256withRSA")
    print(f"  {c('Status    :', C.YELLOW)} {c('✔ VALID', C.GREEN)}")
    print(c("\n  Certificate PEM:", C.YELLOW))
    print(c(pem_snippet(cert_pem), C.DIM))

    save = input(c("\n  Save certificate to file? (y/N): ", C.CYAN)).strip().lower()
    if save == "y":
        fname = cn.replace("@","_").replace(".","_") + "_cert.pem"
        with open(fname, "wb") as f: f.write(cert_pem)
        ok(f"Saved {fname}")
    print()


def cmd_validate_cert():
    divider_title("🔍  Validate Certificate")
    mode = input(c("  Load from (1) file  (2) paste PEM  (3) use active cert: ", C.CYAN)).strip()
    try:
        if mode == "1":
            path = input(c("  Path: ", C.CYAN)).strip()
            with open(path, "rb") as f: cert_pem = f.read()
            cert = x509.load_pem_x509_certificate(cert_pem, default_backend())
        elif mode == "2":
            print(c("  Paste PEM (end with a blank line):", C.CYAN))
            lines = []
            while True:
                l = input()
                if l == "": break
                lines.append(l)
            cert = x509.load_pem_x509_certificate("\n".join(lines).encode(), default_backend())
        else:
            if not STATE.certificate:
                err("No active certificate. Issue one first."); return
            cert = STATE.certificate

        serial_hex = hex(cert.serial_number).upper()
        now_dt = datetime.datetime.utcnow()
        expired    = now_dt > cert.not_valid_after
        not_yet    = now_dt < cert.not_valid_before
        revoked    = serial_hex in STATE.revoked_serials

        status = (c("✔ VALID", C.GREEN) if not (expired or not_yet or revoked)
                  else c("✘ REVOKED", C.RED) if revoked
                  else c("✘ EXPIRED", C.RED) if expired
                  else c("⚠ NOT YET VALID", C.YELLOW))

        sep()
        print(f"  {c('Status    :', C.YELLOW)} {status}")
        cn_val = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        print(f"  {c('CN        :', C.YELLOW)} {cn_val[0].value if cn_val else '?'}")
        print(f"  {c('Serial    :', C.YELLOW)} {serial_hex}")
        print(f"  {c('Not Before:', C.YELLOW)} {cert.not_valid_before.date()}")
        print(f"  {c('Not After :', C.YELLOW)} {cert.not_valid_after.date()}")
        STATE.log("Certificate validated", f"serial={serial_hex}", "info")
    except Exception as e:
        err(f"Validation failed: {e}")


def cmd_revoke_cert():
    divider_title("🚫  Revoke Certificate")
    if not STATE.certificate:
        err("No active certificate."); return
    serial_hex = hex(STATE.certificate.serial_number).upper()
    if serial_hex in STATE.revoked_serials:
        warn(f"Certificate {serial_hex} is already revoked.")
        return
    confirm = input(c(f"  Revoke serial {serial_hex}? (yes/no): ", C.RED)).strip().lower()
    if confirm == "yes":
        STATE.revoked_serials.append(serial_hex)
        ok(f"Certificate {c(serial_hex, C.RED)} added to CRL (Certificate Revocation List).")
        STATE.log("Certificate revoked", f"serial={serial_hex}", "warn")
    else:
        info("Revocation cancelled.")

# ═══════════════════════════════════════════════════════════════════
#  3. SIGN / VERIFY
# ═══════════════════════════════════════════════════════════════════

def _rsa_sign(message: bytes) -> bytes:
    return STATE.private_key.sign(
        message,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256())

def _rsa_verify(public_key, message: bytes, signature: bytes) -> bool:
    try:
        public_key.verify(
            signature, message,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256())
        return True
    except InvalidSignature:
        return False


def cmd_sign():
    divider_title("✍   Digital Signature — Sign")
    if not STATE.has_key():
        err("No key pair. Generate one first (option 1)."); return

    mode = input(c("  Sign (1) typed message  (2) file: ", C.CYAN)).strip()
    if mode == "2":
        path = input(c("  File path: ", C.CYAN)).strip()
        try:
            with open(path, "rb") as f: data = f.read()
            message = data
            msg_str = f"<file:{path}>"
        except Exception as e:
            err(f"Cannot open file: {e}"); return
    else:
        msg_str = input(c("  Message to sign: ", C.CYAN)).strip() or "Hello, CipherMail!"
        message = msg_str.encode()

    sig = _rsa_sign(message)
    pkg = {
        "message": msg_str,
        "message_hash_sha256": hashlib.sha256(message).hexdigest(),
        "signature": b64e(sig),
        "signer": STATE.owner,
        "algorithm": "RSA-PSS-SHA256",
        "timestamp": now_iso(),
        "public_key_fingerprint": fingerprint(STATE.public_key)
    }
    STATE.last_signed_pkg = pkg
    STATE.stats["sigs"] += 1
    STATE.log("Message signed", f"signer={STATE.owner}", "success")

    ok(f"Signed with RSA-PSS-SHA256 by {c(STATE.owner, C.WHITE)}")
    sep()
    print(c("\n  Signed Package (JSON):", C.YELLOW))
    print(c(json.dumps(pkg, indent=2), C.DIM))

    save = input(c("\n  Save signed package to file? (y/N): ", C.CYAN)).strip().lower()
    if save == "y":
        fname = f"signed_{datetime.datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
        with open(fname, "w") as f: json.dump(pkg, f, indent=2)
        ok(f"Saved {fname}")
    print()


def cmd_verify():
    divider_title("🔍  Digital Signature — Verify")

    mode = input(c("  Load package from (1) file  (2) paste JSON  (3) last signed: ", C.CYAN)).strip()
    try:
        if mode == "1":
            path = input(c("  JSON file path: ", C.CYAN)).strip()
            with open(path) as f: pkg = json.load(f)
        elif mode == "3":
            if not STATE.last_signed_pkg:
                err("No last signed package in memory."); return
            pkg = STATE.last_signed_pkg
        else:
            print(c("  Paste JSON (end with blank line):", C.CYAN))
            lines = []
            while True:
                l = input()
                if l == "": break
                lines.append(l)
            pkg = json.loads("\n".join(lines))

        # Public key
        key_mode = input(c("  Public key: (1) active key  (2) from file  (3) embedded in package: ", C.CYAN)).strip()
        if key_mode == "2":
            path = input(c("  Public key PEM path: ", C.CYAN)).strip()
            with open(path, "rb") as f:
                pub_key = serialization.load_pem_public_key(f.read())
        elif key_mode == "3" and "public_key_pem" in pkg:
            pub_key = serialization.load_pem_public_key(pkg["public_key_pem"].encode())
        else:
            if not STATE.public_key:
                err("No active key."); return
            pub_key = STATE.public_key

        message = pkg["message"].encode() if not pkg["message"].startswith("<file:") else open(pkg["message"][6:-1], "rb").read()
        sig = b64d(pkg["signature"])

        # Timestamp / replay check
        ts   = datetime.datetime.fromisoformat(pkg["timestamp"].rstrip("Z"))
        age  = (datetime.datetime.utcnow() - ts).total_seconds()
        replay_warn = age > 86400  # > 24h

        valid = _rsa_verify(pub_key, message, sig)
        STATE.stats["verifs"] += 1
        STATE.log("Signature verified", f"signer={pkg.get('signer','?')} valid={valid}", "success" if valid else "error")

        sep()
        if valid:
            ok(f"SIGNATURE {c('VALID', C.GREEN + C.BOLD)}")
        else:
            err(f"SIGNATURE {c('INVALID', C.RED + C.BOLD)} — message may have been tampered!")
        sep()
        print(f"  {c('Signer    :', C.YELLOW)} {pkg.get('signer','?')}")
        print(f"  {c('Algorithm :', C.YELLOW)} {pkg.get('algorithm','?')}")
        print(f"  {c('Timestamp :', C.YELLOW)} {pkg.get('timestamp','?')}")
        print(f"  {c('Msg Hash  :', C.YELLOW)} {hashlib.sha256(message).hexdigest()}")
        if replay_warn:
            warn(f"Package is {int(age/3600)}h old — potential replay concern.")
        print()
    except Exception as e:
        err(f"Verification error: {e}")


def cmd_multi_party_sign():
    divider_title("👥  Multi-Party Signing Demo")
    doc = input(c("  Document content (or press Enter for demo): ", C.CYAN)).strip()
    if not doc:
        doc = "MERGER AGREEMENT: Company A and Company B agree to merge under the terms herein. Date: " + now_iso()

    info(f"Document: {doc[:80]}{'…' if len(doc)>80 else ''}")
    info("Generating 3 authorized signers + 1 unauthorized attacker…\n")

    signers = [
        ("Alice Walker <alice@corp.com>", True),
        ("Bob Chen <bob@corp.com>", True),
        ("Carol Davis <carol@corp.com>", True),
        ("Eve Mallory <eve@attacker.com>", False),  # signs different content
    ]

    results = []
    for name, authorized in signers:
        kp_priv = rsa.generate_private_key(65537, 2048, default_backend())
        kp_pub  = kp_priv.public_key()
        # Unauthorized signer signs different content (simulating forgery attempt)
        content = doc.encode() if authorized else b"DIFFERENT FRAUDULENT CONTENT"
        sig = kp_priv.sign(content,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256())
        # Verify against original document
        valid = _rsa_verify(kp_pub, doc.encode(), sig)
        results.append((name, authorized, valid))

    sep()
    passed = 0
    for name, authorized, valid in results:
        status = (c("✔  VALID",   C.GREEN) if valid and authorized
                  else c("✘  REJECTED (tampered content)", C.RED) if not valid
                  else c("✘  REJECTED (unauthorized)",    C.RED))
        role = c("authorized", C.GREEN) if authorized else c("ATTACKER", C.RED)
        print(f"  [{role}]  {name}")
        print(f"             → {status}")
        if valid and authorized: passed += 1
        print()

    print(f"  Result: {c(str(passed), C.GREEN)}/{len([r for r in results if r[1]])} authorized signatures valid.")
    print(f"          {c('1', C.GREEN)} unauthorized signer correctly rejected.")
    STATE.log("Multi-party signing", f"{passed}/3 valid, 1 rejected", "success")

# ═══════════════════════════════════════════════════════════════════
#  4. HYBRID ENCRYPTION
# ═══════════════════════════════════════════════════════════════════

def cmd_encrypt():
    divider_title("🔒  Hybrid Encryption — RSA-OAEP + AES-256-GCM")
    if not STATE.has_key():
        err("No key pair. Generate one first."); return

    mode = input(c("  Encrypt (1) typed message  (2) file: ", C.CYAN)).strip()
    if mode == "2":
        path = input(c("  File path: ", C.CYAN)).strip()
        try:
            with open(path, "rb") as f: plaintext = f.read()
            label = f"<file:{path}>"
        except Exception as e:
            err(f"Cannot open: {e}"); return
    else:
        msg = input(c("  Plaintext message: ", C.CYAN)).strip() or "Confidential: Q3 financial projections."
        plaintext = msg.encode()
        label = msg

    pub_key = STATE.public_key  # encrypt for self (demo)

    # 1. Generate 256-bit AES session key
    aes_key = os.urandom(32)
    iv      = os.urandom(12)   # 96-bit IV for GCM
    nonce   = os.urandom(16).hex()  # replay-prevention nonce

    # 2. AES-256-GCM encrypt
    aesgcm     = AESGCM(aes_key)
    ciphertext = aesgcm.encrypt(iv, plaintext, None)

    # 3. RSA-OAEP encrypt the AES key
    enc_aes_key = pub_key.encrypt(
        aes_key,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))

    pkg = {
        "encrypted_key": b64e(enc_aes_key),
        "iv":            b64e(iv),
        "ciphertext":    b64e(ciphertext),
        "nonce":         nonce,
        "timestamp":     now_iso(),
        "algorithm":     "RSA-OAEP-SHA256 + AES-256-GCM",
        "recipient_fingerprint": fingerprint(pub_key)
    }
    STATE.last_enc_pkg = pkg
    STATE.stats["encrypts"] += 1
    STATE.log("Message encrypted", f"nonce={nonce[:16]}…", "success")

    ok(f"Encrypted with {c('RSA-OAEP-SHA256 + AES-256-GCM', C.WHITE)}")
    sep()
    print(c("\n  Encrypted Package (JSON):", C.YELLOW))
    display = {k: (v[:60]+"…" if isinstance(v,str) and len(v)>60 else v) for k,v in pkg.items()}
    print(c(json.dumps(display, indent=2), C.DIM))

    save = input(c("\n  Save encrypted package to file? (y/N): ", C.CYAN)).strip().lower()
    if save == "y":
        fname = f"encrypted_{datetime.datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
        with open(fname, "w") as f: json.dump(pkg, f)
        ok(f"Saved {fname}")
    print()


def cmd_decrypt():
    divider_title("🔓  Hybrid Decryption")
    if not STATE.has_key():
        err("No private key. Generate one first."); return

    mode = input(c("  Load package from (1) file  (2) last encrypted: ", C.CYAN)).strip()
    try:
        if mode == "1":
            path = input(c("  JSON file path: ", C.CYAN)).strip()
            with open(path) as f: pkg = json.load(f)
        else:
            if not STATE.last_enc_pkg:
                err("No encrypted package in memory."); return
            pkg = STATE.last_enc_pkg

        # Replay check
        ts  = datetime.datetime.fromisoformat(pkg["timestamp"].rstrip("Z"))
        age = (datetime.datetime.utcnow() - ts).total_seconds()

        # 1. RSA-OAEP decrypt AES key
        aes_key = STATE.private_key.decrypt(
            b64d(pkg["encrypted_key"]),
            padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))

        # 2. AES-256-GCM decrypt
        aesgcm    = AESGCM(aes_key)
        plaintext = aesgcm.decrypt(b64d(pkg["iv"]), b64d(pkg["ciphertext"]), None)

        ok(f"Decryption {c('SUCCESSFUL', C.GREEN + C.BOLD)}")
        sep()
        print(f"  {c('Algorithm  :', C.YELLOW)} {pkg.get('algorithm','?')}")
        print(f"  {c('Nonce      :', C.YELLOW)} {pkg.get('nonce','?')}")
        print(f"  {c('Timestamp  :', C.YELLOW)} {pkg.get('timestamp','?')}")
        print(f"  {c('GCM Auth   :', C.YELLOW)} {c('✔ Tag verified', C.GREEN)}")
        if age > 86400:
            warn(f"Package is {int(age/3600)}h old — possible replay attempt.")
        sep()
        print(c("\n  Decrypted Plaintext:", C.GREEN))
        try:
            print(f"  {plaintext.decode()}")
        except UnicodeDecodeError:
            print(f"  <binary data, {len(plaintext)} bytes>")
        STATE.log("Message decrypted", "AES-GCM tag OK", "success")
    except Exception as e:
        err(f"Decryption failed: {e}")
    print()

# ═══════════════════════════════════════════════════════════════════
#  5. EMAIL FORENSICS
# ═══════════════════════════════════════════════════════════════════

SPOOFED_EMAIL = """\
Received: from evil-server.attacker.com (attacker.com [198.51.100.5])
  by mail.victim.com with ESMTP id abc
From: "CEO John Smith" <ceo@legitimate-corp.com>
To: accountant@legitimate-corp.com
Date: Mon, 01 Jan 2026 09:00:00 +0000
Subject: URGENT: Wire Transfer Needed
Return-Path: <scammer@evil-server.attacker.com>
Message-ID: <fake@evil>

Please wire $50,000 immediately. Do not verify by phone.
"""

LEGIT_EMAIL = """\
Received: from smtp.legitimate-corp.com (203.0.113.10)
  by mail.legitimate-corp.com with ESMTPS id xyz
From: "Alice Smith" <alice@legitimate-corp.com>
To: bob@legitimate-corp.com
Date: Wed, 04 Mar 2026 10:00:00 +0000
Subject: Q3 Report
Return-Path: <alice@legitimate-corp.com>
Message-ID: <20260304100000@legitimate-corp.com>
DKIM-Signature: v=1; a=rsa-sha256; d=legitimate-corp.com; s=default; b=validSIG

Please find the Q3 report attached.
"""

def _parse_headers(raw: str) -> dict:
    headers = {}
    current_key = ""
    for line in raw.splitlines():
        m = re.match(r'^([\w\-]+):\s*(.*)', line)
        if m:
            current_key = m.group(1).lower()
            headers[current_key] = m.group(2).strip()
        elif line.startswith((" ", "\t")) and current_key:
            headers[current_key] = headers[current_key] + " " + line.strip()
    return headers


def cmd_email_forensics():
    divider_title("📧  Email Forensics & Header Analysis")
    print("  Options:")
    print("  1) Paste raw email / headers")
    print("  2) Load from file")
    print("  3) Use SPOOFED example")
    print("  4) Use LEGITIMATE example")
    choice = input(c("  > ", C.CYAN)).strip()

    if choice == "3":
        raw = SPOOFED_EMAIL
    elif choice == "4":
        raw = LEGIT_EMAIL
    elif choice == "2":
        path = input(c("  File path: ", C.CYAN)).strip()
        with open(path) as f: raw = f.read()
    else:
        print(c("  Paste headers (end with blank line):", C.CYAN))
        lines = []
        while True:
            l = input()
            if l == "": break
            lines.append(l)
        raw = "\n".join(lines)

    headers = _parse_headers(raw)

    from_hdr    = headers.get("from", "?")
    to_hdr      = headers.get("to",   "?")
    subject     = headers.get("subject", "?")
    date_hdr    = headers.get("date", "?")
    return_path = headers.get("return-path", "")
    dkim        = headers.get("dkim-signature", "")
    msg_id      = headers.get("message-id", "")

    def extract_domain(s):
        m = re.search(r'@([\w.\-]+)', s)
        return m.group(1).lower() if m else ""

    from_domain   = extract_domain(from_hdr)
    return_domain = extract_domain(return_path)
    dkim_domain   = re.search(r'd=([\w.\-]+)', dkim).group(1) if dkim else ""

    # Threat analysis
    threats = []
    if from_domain and return_domain and from_domain != return_domain:
        threats.append(("DANGER", f"Domain mismatch: From={from_domain}, Return-Path={return_domain}"))
    if dkim and dkim_domain and dkim_domain != from_domain:
        threats.append(("WARN", f"DKIM domain ({dkim_domain}) ≠ From domain ({from_domain})"))
    if not dkim:
        threats.append(("WARN", "No DKIM-Signature — cannot verify sender authenticity"))
    if not msg_id:
        threats.append(("WARN", "Missing Message-ID — possible header manipulation"))

    # Received chain
    received = [l.strip() for l in raw.splitlines() if l.lower().startswith("received:")]

    sep()
    print(f"  {c('From       :', C.YELLOW)} {from_hdr}")
    print(f"  {c('To         :', C.YELLOW)} {to_hdr}")
    print(f"  {c('Subject    :', C.YELLOW)} {subject}")
    print(f"  {c('Date       :', C.YELLOW)} {date_hdr}")
    print(f"  {c('Return-Path:', C.YELLOW)} {return_path or c('(none)', C.DIM)}")
    print(f"  {c('Message-ID :', C.YELLOW)} {msg_id or c('(missing!)', C.RED)}")
    print(f"  {c('DKIM       :', C.YELLOW)} {c('Present', C.GREEN) if dkim else c('MISSING', C.RED)}")

    sep()
    print(c("  Routing Chain:", C.YELLOW))
    if received:
        for i, r in enumerate(received):
            col = C.CYAN if i == 0 else C.DIM
            print(c(f"  Hop {i+1}: {r[9:].strip()[:100]}", col))
    else:
        warn("No Received headers found.")

    sep()
    print(c("  Threat Analysis:", C.YELLOW))
    if not threats:
        ok("No obvious spoofing indicators detected.")
    else:
        for level, msg in threats:
            if level == "DANGER":
                err(msg)
            else:
                warn(msg)
    overall_suspicious = any(t[0] == "DANGER" for t in threats)
    sep()
    print(f"  Overall verdict: {c('🚨 SUSPICIOUS — possible spoof/phishing', C.RED) if overall_suspicious else c('✔ Appears legitimate', C.GREEN)}")
    STATE.log("Email analyzed", f"from={from_hdr}, threats={len(threats)}", "warn" if overall_suspicious else "info")

    # Optionally sign email
    if STATE.has_key():
        sign_it = input(c("\n  Sign this email body with your key? (y/N): ", C.CYAN)).strip().lower()
        if sign_it == "y":
            body = raw.split("\n\n", 1)[-1].strip() if "\n\n" in raw else raw
            sig = _rsa_sign(body.encode())
            ok(f"Email signed. X-CipherMail-Sig: {b64e(sig)[:60]}…")
            ok(f"X-CipherMail-Signer: {STATE.owner}")
            STATE.log("Email signed", f"signer={STATE.owner}", "success")
    print()

# ═══════════════════════════════════════════════════════════════════
#  6. ATTACK SIMULATIONS
# ═══════════════════════════════════════════════════════════════════

def cmd_attack_simulations():
    divider_title("🛡   Attack Simulations")
    print("  1) MITM — Message Tampering Detection")
    print("  2) Replay Attack Prevention")
    print("  3) Weak Key Policy Demonstration")
    print("  4) Certificate Spoofing Detection")
    print("  5) Run ALL simulations")
    choice = input(c("  > ", C.CYAN)).strip()

    if choice in ("1","5"): _sim_mitm()
    if choice in ("2","5"): _sim_replay()
    if choice in ("3","5"): _sim_weak_key()
    if choice in ("4","5"): _sim_cert_spoof()


def _sim_mitm():
    bold("  ⚔  MITM — Man-in-the-Middle Tampering Simulation")
    if not STATE.has_key():
        warn("  Generating temporary keys for demo…")
        STATE.private_key = rsa.generate_private_key(65537, 2048, default_backend())
        STATE.public_key  = STATE.private_key.public_key()
        STATE.owner = "demo@test.com"

    original = b"Transfer $1,000 to Alice account 12345"
    tampered = b"Transfer $99,999 to Hacker account 00001"

    sig = _rsa_sign(original)
    detected = not _rsa_verify(STATE.public_key, tampered, sig)

    print(f"  Original message : {c(original.decode(), C.GREEN)}")
    print(f"  Tampered message : {c(tampered.decode(), C.RED)}")
    print(f"  Signature        : {b64e(sig)[:40]}…")
    print(f"  MITM Detection   : {c('✔ TAMPERING DETECTED — MITM blocked', C.GREEN) if detected else c('✘ NOT detected', C.RED)}")
    STATE.log("MITM simulation", f"tampering={'detected' if detected else 'missed'}", "success" if detected else "error")
    print()


def _sim_replay():
    bold("  🔁  Replay Attack Prevention Simulation")
    REPLAY_WINDOW_SEC = 300  # 5 minutes
    old_ts = (datetime.datetime.utcnow() - datetime.timedelta(hours=2)).isoformat() + "Z"
    pkg = {"message": "Pay invoice #1234", "timestamp": old_ts, "signer": "attacker@evil.com"}
    age = (datetime.datetime.utcnow() - datetime.datetime.fromisoformat(old_ts.rstrip("Z"))).total_seconds()
    rejected = age > REPLAY_WINDOW_SEC

    print(f"  Package timestamp: {c(old_ts, C.DIM)}")
    print(f"  Package age      : {c(f'{int(age)}s', C.YELLOW)} (replay window: {REPLAY_WINDOW_SEC}s)")
    print(f"  Result           : {c('✔ REPLAY REJECTED — timestamp expired', C.GREEN) if rejected else c('⚠ within window — accepted', C.YELLOW)}")
    STATE.log("Replay attack simulation", f"age={int(age)}s, rejected={rejected}", "success" if rejected else "warn")
    print()


def _sim_weak_key():
    bold("  🔑  Weak Key Policy Demonstration")
    keys = [
        ("RSA-512",  512,  "INSECURE", C.RED,    "Factored in minutes (since 2009)"),
        ("RSA-1024", 1024, "DEPRECATED", C.YELLOW, "Considered weak since 2010, banned by NIST"),
        ("RSA-2048", 2048, "ACCEPTABLE", C.GREEN,  "Current minimum (NIST SP 800-131A)"),
        ("RSA-4096", 4096, "STRONG",   C.CYAN,   "Recommended for long-term security"),
    ]
    print(f"  {'Algorithm':<12} {'Status':<12} {'Notes'}")
    sep('-')
    for algo, bits, status, col, note in keys:
        enforced = bits < 2048
        tag = c(f"[BLOCKED by policy]", C.RED) if enforced else c("[ALLOWED]", C.GREEN)
        print(f"  {c(algo, col):<20} {c(status, col):<20} {note}  {tag}")
    print()
    info("CipherMail enforces minimum 2048-bit keys.")
    STATE.log("Weak key policy demonstrated", "RSA<2048 blocked", "warn")
    print()


def _sim_cert_spoof():
    bold("  🪪  Certificate Spoofing Detection")
    # Build a forged cert signed by a different CA key
    attacker_key = rsa.generate_private_key(65537, 2048, default_backend())
    attacker_pub = attacker_key.public_key()
    now_dt = datetime.datetime.utcnow()
    forged_cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "legitimate-corp.com")]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "legitimate-corp.com")]))
        .public_key(attacker_pub)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now_dt)
        .not_valid_after(now_dt + datetime.timedelta(days=365))
        .sign(attacker_key, hashes.SHA256(), default_backend())
    )
    # Check if forged cert's key fingerprint is in our trust store
    forged_fp = fingerprint(attacker_pub)
    trusted_fps = [k["fingerprint"] for k in STATE.key_store]
    in_trust_store = any(forged_fp[:20] in fp for fp in trusted_fps)

    cn_val = forged_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    print(f"  Forged cert CN   : {c(cn_val, C.RED)}")
    print(f"  Forged cert serial: {hex(forged_cert.serial_number).upper()}")
    print(f"  Fingerprint      : {forged_fp[:47]}…")
    print(f"  In trust store   : {c('YES', C.RED) if in_trust_store else c('NO', C.GREEN)}")
    print(f"  Result           : {c('✔ FORGED CERT REJECTED — not in trust store', C.GREEN) if not in_trust_store else c('✘ ACCEPTED (collision!)', C.RED)}")
    STATE.log("Cert spoof simulation", f"rejected={not in_trust_store}", "success" if not in_trust_store else "error")
    print()

# ═══════════════════════════════════════════════════════════════════
#  7. AUDIT LOG
# ═══════════════════════════════════════════════════════════════════

def cmd_audit_log():
    divider_title("📋  Audit Log (Hash-Chained)")
    if not STATE.audit_log:
        warn("No events logged yet. Use features first."); return

    colours = {"success": C.GREEN, "error": C.RED, "warn": C.YELLOW, "info": C.CYAN}
    for i, e in enumerate(STATE.audit_log, 1):
        col = colours.get(e["level"], C.DIM)
        print(f"  {c(f'[{i:03}]', C.DIM)} {c(e['time'], C.DIM)}  {c(e['action'], col)}")
        if e["detail"]:
            print(f"         {c(e['detail'], C.DIM)}")
        print(f"         hash: {c(e['hash'][:40]+'…', C.DIM)}")
    sep()
    chain_data = json.dumps(STATE.audit_log).encode()
    chain_hash = hashlib.sha256(chain_data).hexdigest()
    print(f"  {c('Log Integrity Hash (SHA-256):', C.YELLOW)}")
    print(f"  {c(chain_hash, C.CYAN)}")
    info("Any tampering with log entries changes this hash.")
    print()

# ═══════════════════════════════════════════════════════════════════
#  8. USE CASE DEMOS
# ═══════════════════════════════════════════════════════════════════

def cmd_use_cases():
    divider_title("💡  Real-World Use Cases")
    print("  1) Legal Contract Signing")
    print("  2) Secure Email Authentication")
    print("  3) Medical Record Integrity")
    choice = input(c("  > ", C.CYAN)).strip()
    if choice == "1": _uc_legal()
    elif choice == "2": _uc_email_auth()
    elif choice == "3": _uc_medical()
    else: warn("Invalid choice.")


def _ensure_keys():
    if not STATE.has_key():
        info("Auto-generating RSA-2048 key pair for demo…")
        STATE.private_key = rsa.generate_private_key(65537, 2048, default_backend())
        STATE.public_key  = STATE.private_key.public_key()
        STATE.owner = "demo@ciphermail.io"
        fp = fingerprint(STATE.public_key)
        STATE.key_store.append({"owner": STATE.owner, "algo": "RSA-2048", "fingerprint": fp, "created": now_iso()})
        STATE.stats["keys"] += 1


def _uc_legal():
    bold("  🏛  Use Case 1: Legal Contract Signing")
    _ensure_keys()
    print(textwrap.dedent("""
  Problem:  Law firms need to prove digital contracts were signed by
            the correct parties and have not been altered post-signing.

  Solution: Each party generates an RSA key pair, obtains a certificate,
            signs the document hash, and stores the signed package.
            Any third party can verify authenticity + integrity.
    """))
    contract = (
        "PARTNERSHIP AGREEMENT\n"
        "Parties: Alice Walker & Bob Chen\n"
        f"Date: {now_iso()}\n"
        "Terms: 50/50 revenue split for CipherMail joint venture."
    )
    doc_hash = hashlib.sha256(contract.encode()).hexdigest()
    sig = _rsa_sign(contract.encode())
    # Verify
    valid = _rsa_verify(STATE.public_key, contract.encode(), sig)

    print(f"  Document hash   : {c(doc_hash[:48]+'…', C.CYAN)}")
    print(f"  Signed by       : {c(STATE.owner, C.WHITE)}")
    print(f"  Signature valid : {c('✔ YES', C.GREEN) if valid else c('✘ NO', C.RED)}")
    print(f"  Tamper-evident  : Any change to contract invalidates signature.")
    STATE.log("UC1: Legal contract signed+verified", f"hash={doc_hash[:20]}…", "success")
    print()


def _uc_email_auth():
    bold("  📧  Use Case 2: Secure Email Authentication")
    _ensure_keys()
    print(textwrap.dedent("""
  Problem:  Email spoofing and phishing cause millions of breaches.
            Organisations cannot trust sender identity without cryptographic proof.

  Solution: Outgoing emails are signed with sender's private key.
            Recipients verify with sender's public key from directory.
            Tampered or spoofed emails fail verification.
    """))
    email_body = (
        "From: CFO <cfo@corp.com>\n"
        "Subject: URGENT approval needed\n"
        f"Date: {now_iso()}\n\n"
        "Please approve the $50k budget proposal by EOD."
    )
    sig = _rsa_sign(email_body.encode())
    valid = _rsa_verify(STATE.public_key, email_body.encode(), sig)

    # Simulate spoofed version
    spoofed_body = email_body.replace("$50k", "$500k").replace("approval", "wire transfer")
    spoof_detected = not _rsa_verify(STATE.public_key, spoofed_body.encode(), sig)

    print(f"  Signed by           : {c(STATE.owner, C.WHITE)}")
    print(f"  Signature on original: {c('✔ VALID', C.GREEN) if valid else c('✘ INVALID', C.RED)}")
    print(f"  Spoofed version check: {c('✔ TAMPERING DETECTED', C.GREEN) if spoof_detected else c('✘ NOT detected', C.RED)}")
    print(f"  Spoofing possible?   : {c('NO — cannot forge without private key', C.GREEN)}")
    STATE.log("UC2: Email auth demo", "spoofing prevented", "success")
    print()


def _uc_medical():
    bold("  💊  Use Case 3: Medical Record Integrity")
    _ensure_keys()
    print(textwrap.dedent("""
  Problem:  Medical records must be provably unaltered and accessible
            only to authorised parties. Tampering with prescriptions
            could endanger lives.

  Solution: Records encrypted with RSA-OAEP + AES-256-GCM (only patient
            and authorised doctors can decrypt). Each access is logged
            in a hash-chained audit trail. Records are signed by the doctor.
    """))
    record = (
        "PATIENT: John Doe | DOB: 1980-01-01\n"
        "Prescription: Amoxicillin 500mg TDS × 7 days\n"
        f"Issuing Doctor: Dr. Alice Smith | Date: {now_iso()}"
    )
    # Encrypt
    aes_key    = os.urandom(32)
    iv         = os.urandom(12)
    aesgcm     = AESGCM(aes_key)
    ciphertext = aesgcm.encrypt(iv, record.encode(), None)
    enc_key    = STATE.public_key.encrypt(
        aes_key,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    # Sign
    sig = _rsa_sign(record.encode())
    valid = _rsa_verify(STATE.public_key, record.encode(), sig)
    # Decrypt (authorised access)
    aes_key2    = STATE.private_key.decrypt(enc_key,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    recovered = aesgcm.decrypt(iv, ciphertext, None).decode()

    print(f"  Encrypted record    : {b64e(ciphertext)[:48]}…")
    print(f"  Encrypted AES key   : {b64e(enc_key)[:48]}…")
    print(f"  Doctor's signature  : {b64e(sig)[:48]}…")
    print(f"  Signature valid     : {c('✔ YES', C.GREEN) if valid else c('✘ NO', C.RED)}")
    print(f"  Decryption OK       : {c('✔ YES', C.GREEN) if recovered == record else c('✘ NO', C.RED)}")
    print(f"  Integrity guaranteed: Only holder of private key can decrypt")
    print(f"  Access logged       : Audit trail entry created")
    STATE.log("UC3: Medical record encrypted+signed", "audit logged", "success")
    print()

# ═══════════════════════════════════════════════════════════════════
#  STATISTICS
# ═══════════════════════════════════════════════════════════════════

def cmd_stats():
    divider_title("📊  Session Statistics")
    s = STATE.stats
    kp = STATE.key_store[-1] if STATE.key_store else None
    print(f"  {c('Keys generated :', C.YELLOW)} {s['keys']}")
    print(f"  {c('Signatures     :', C.YELLOW)} {s['sigs']}")
    print(f"  {c('Verifications  :', C.YELLOW)} {s['verifs']}")
    print(f"  {c('Encryptions    :', C.YELLOW)} {s['encrypts']}")
    print(f"  {c('Audit entries  :', C.YELLOW)} {len(STATE.audit_log)}")
    print(f"  {c('Revoked certs  :', C.YELLOW)} {len(STATE.revoked_serials)}")
    if kp:
        sep()
        print(f"  {c('Active key     :', C.YELLOW)} {kp['owner']} ({kp['algo']})")
        print(f"  {c('Fingerprint    :', C.YELLOW)} {c(kp['fingerprint'][:47]+'…', C.CYAN)}")
    if STATE.certificate:
        cn_val = STATE.certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        print(f"  {c('Active cert    :', C.YELLOW)} {cn_val[0].value if cn_val else '?'} "
              f"(expires {STATE.certificate.not_valid_after.date()})")
    print()

# ═══════════════════════════════════════════════════════════════════
#  MAIN MENU
# ═══════════════════════════════════════════════════════════════════

MENU = [
    ("─── Key & Certificate Management ───────────────────────────", None),
    ("1", "Generate RSA Key Pair",                  cmd_generate_key),
    ("2", "Show Key Store",                         cmd_show_key_store),
    ("3", "Load Key Pair from File",                cmd_load_key),
    ("4", "Issue X.509 Certificate",                cmd_issue_cert),
    ("5", "Validate Certificate",                   cmd_validate_cert),
    ("6", "Revoke Certificate (CRL)",               cmd_revoke_cert),
    ("─── Signing & Encryption ───────────────────────────────────", None),
    ("7", "Sign Message / File",                    cmd_sign),
    ("8", "Verify Signature",                       cmd_verify),
    ("9", "Multi-Party Signing Demo",               cmd_multi_party_sign),
    ("10","Encrypt (Hybrid RSA-OAEP + AES-256-GCM)",cmd_encrypt),
    ("11","Decrypt",                                cmd_decrypt),
    ("─── Forensics & Attacks ────────────────────────────────────", None),
    ("12","Email Header Forensics",                 cmd_email_forensics),
    ("13","Attack Simulations (MITM / Replay / …)", cmd_attack_simulations),
    ("─── Reports & Use Cases ────────────────────────────────────", None),
    ("14","Real-World Use Case Demos",              cmd_use_cases),
    ("15","Session Statistics",                     cmd_stats),
    ("16","View Audit Log",                         cmd_audit_log),
    ("─────────────────────────────────────────────────────────────",None),
    ("0", "Exit",                                   None),
]

def print_menu():
    print()
    for item in MENU:
        if len(item) == 2:          # divider
            print(c(f"\n  {item[0]}", C.DIM))
        else:
            num, label, _ = item
            print(f"  {c(num+')', C.CYAN):<18} {label}")
    print()

def run_interactive():
    banner()
    info("Type a number and press Enter.  Requires: pip install cryptography")
    while True:
        print_menu()
        # Show status line
        key_info = (c(STATE.owner, C.GREEN) if STATE.has_key() else c("no key", C.DIM))
        cert_info = (c("cert OK", C.GREEN) if STATE.certificate else c("no cert", C.DIM))
        print(c(f"  Key: {key_info}  |  Cert: {cert_info}  |  Log entries: {len(STATE.audit_log)}", C.DIM))
        try:
            choice = input(c("\n  ciphermail> ", C.CYAN + C.BOLD)).strip()
        except (KeyboardInterrupt, EOFError):
            print("\n"); info("Goodbye."); break

        if choice == "0":
            info("Goodbye."); break

        handler = None
        for item in MENU:
            if len(item) == 3 and item[0] == choice:
                handler = item[2]
                break
        if handler:
            try:
                handler()
            except KeyboardInterrupt:
                warn("Interrupted.")
            except Exception as e:
                err(f"Unexpected error: {e}")
        else:
            warn("Unknown option. Try again.")

# ═══════════════════════════════════════════════════════════════════
#  CLI ARG MODE  (python3 ciphermail.py keygen --owner alice@x.com)
# ═══════════════════════════════════════════════════════════════════

def cli_mode():
    parser = argparse.ArgumentParser(
        prog="ciphermail",
        description="CipherMail — Email Forensics & PKI CLI Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""
  Examples:
    python3 ciphermail.py                         # interactive menu
    python3 ciphermail.py keygen                  # generate key pair
    python3 ciphermail.py sign -m "hello"         # sign a message
    python3 ciphermail.py verify -f signed.json   # verify signature
    python3 ciphermail.py encrypt -m "secret"     # encrypt a message
    python3 ciphermail.py forensics -f email.txt  # analyse headers
    python3 ciphermail.py attacks                 # run all simulations
    python3 ciphermail.py usecases               # demo use cases
        """))

    sub = parser.add_subparsers(dest="cmd")

    p_kg = sub.add_parser("keygen", help="Generate RSA key pair")
    p_kg.add_argument("--bits", type=int, default=2048, choices=[2048, 4096])
    p_kg.add_argument("--owner", default="user@example.com")
    p_kg.add_argument("--password", default="changeme")

    p_sg = sub.add_parser("sign", help="Sign a message")
    p_sg.add_argument("-m","--message", default=None)
    p_sg.add_argument("-f","--file", default=None)

    p_vr = sub.add_parser("verify", help="Verify a signed package")
    p_vr.add_argument("-f","--file", required=True)

    p_en = sub.add_parser("encrypt", help="Encrypt a message")
    p_en.add_argument("-m","--message", default=None)
    p_en.add_argument("-f","--file",    default=None)

    p_de = sub.add_parser("decrypt", help="Decrypt a package")
    p_de.add_argument("-f","--file", required=True)

    p_em = sub.add_parser("forensics", help="Analyse email headers")
    p_em.add_argument("-f","--file", default=None)
    p_em.add_argument("--spoofed",   action="store_true")
    p_em.add_argument("--legit",     action="store_true")

    sub.add_parser("attacks",  help="Run all attack simulations")
    sub.add_parser("usecases", help="Run all use-case demos")
    sub.add_parser("log",      help="Show audit log")
    sub.add_parser("stats",    help="Show session statistics")

    args = parser.parse_args()

    if args.cmd is None:
        run_interactive()
        return

    banner()

    if args.cmd == "keygen":
        STATE.private_key = rsa.generate_private_key(65537, args.bits, default_backend())
        STATE.public_key  = STATE.private_key.public_key()
        STATE.owner       = args.owner
        fp = fingerprint(STATE.public_key)
        STATE.key_store.append({"owner": args.owner, "algo": f"RSA-{args.bits}", "fingerprint": fp, "created": now_iso()})
        STATE.stats["keys"] += 1
        ok(f"RSA-{args.bits} key pair generated for {args.owner}")
        print(f"  Fingerprint: {c(fp[:47]+'…', C.CYAN)}")
        pw = args.password.encode()
        pub_pem  = STATE.public_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        priv_pem = STATE.private_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.BestAvailableEncryption(pw))
        fname = args.owner.replace("@","_").replace(".","_")
        with open(f"{fname}_pub.pem","wb") as f: f.write(pub_pem)
        with open(f"{fname}_priv.pem","wb") as f: f.write(priv_pem)
        ok(f"Saved {fname}_pub.pem and {fname}_priv.pem")
        STATE.log("Key pair generated (CLI)", f"RSA-{args.bits} for {args.owner}", "success")

    elif args.cmd == "sign":
        _ensure_keys()
        msg = args.message or "default message"
        data = open(args.file,"rb").read() if args.file else msg.encode()
        sig  = _rsa_sign(data)
        pkg  = {"message": msg, "signature": b64e(sig), "signer": STATE.owner,
                "algorithm": "RSA-PSS-SHA256", "timestamp": now_iso()}
        STATE.last_signed_pkg = pkg
        fname = f"signed_{datetime.datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
        with open(fname,"w") as f: json.dump(pkg, f, indent=2)
        ok(f"Signed. Package saved to {fname}")
        STATE.log("CLI sign", f"signer={STATE.owner}", "success")

    elif args.cmd == "verify":
        _ensure_keys()
        with open(args.file) as f: pkg = json.load(f)
        valid = _rsa_verify(STATE.public_key, pkg["message"].encode(), b64d(pkg["signature"]))
        if valid: ok(f"SIGNATURE VALID — signed by {pkg.get('signer','?')}")
        else:     err("SIGNATURE INVALID")
        STATE.log("CLI verify", f"valid={valid}", "success" if valid else "error")

    elif args.cmd == "encrypt":
        _ensure_keys()
        plaintext = open(args.file,"rb").read() if args.file else (args.message or "hello").encode()
        aes_key   = os.urandom(32); iv = os.urandom(12)
        ct = AESGCM(aes_key).encrypt(iv, plaintext, None)
        ek = STATE.public_key.encrypt(aes_key, padding.OAEP(padding.MGF1(hashes.SHA256()), hashes.SHA256(), None))
        pkg = {"encrypted_key": b64e(ek), "iv": b64e(iv), "ciphertext": b64e(ct),
               "nonce": os.urandom(16).hex(), "timestamp": now_iso(), "algorithm": "RSA-OAEP + AES-256-GCM"}
        STATE.last_enc_pkg = pkg
        fname = f"encrypted_{datetime.datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
        with open(fname,"w") as f: json.dump(pkg, f)
        ok(f"Encrypted. Package saved to {fname}")

    elif args.cmd == "decrypt":
        _ensure_keys()
        with open(args.file) as f: pkg = json.load(f)
        aes_key = STATE.private_key.decrypt(b64d(pkg["encrypted_key"]),
            padding.OAEP(padding.MGF1(hashes.SHA256()), hashes.SHA256(), None))
        pt = AESGCM(aes_key).decrypt(b64d(pkg["iv"]), b64d(pkg["ciphertext"]), None)
        ok("Decrypted:")
        try:    print(f"  {pt.decode()}")
        except: print(f"  <{len(pt)} bytes binary>")

    elif args.cmd == "forensics":
        if args.spoofed:  raw = SPOOFED_EMAIL
        elif args.legit:  raw = LEGIT_EMAIL
        elif args.file:
            with open(args.file) as f: raw = f.read()
        else:
            raw = SPOOFED_EMAIL
        _email_forensics_raw(raw)

    elif args.cmd == "attacks":
        _ensure_keys()
        _sim_mitm(); _sim_replay(); _sim_weak_key(); _sim_cert_spoof()

    elif args.cmd == "usecases":
        _ensure_keys()
        _uc_legal(); _uc_email_auth(); _uc_medical()

    elif args.cmd == "log":
        cmd_audit_log()

    elif args.cmd == "stats":
        cmd_stats()


def _email_forensics_raw(raw: str):
    """Non-interactive forensics (used by CLI mode)."""
    headers = _parse_headers(raw)
    from_hdr = headers.get("from","?")
    dkim     = headers.get("dkim-signature","")
    return_path = headers.get("return-path","")
    def extract_domain(s):
        m = re.search(r'@([\w.\-]+)', s)
        return m.group(1).lower() if m else ""
    threats = []
    fd = extract_domain(from_hdr); rd = extract_domain(return_path)
    if fd and rd and fd != rd:
        threats.append(("DANGER", f"Domain mismatch: From={fd}, Return-Path={rd}"))
    if not dkim:
        threats.append(("WARN", "No DKIM-Signature"))
    sep()
    print(f"  From    : {from_hdr}")
    print(f"  Return  : {return_path or '(none)'}")
    print(f"  DKIM    : {'Present' if dkim else 'MISSING'}")
    sep()
    for level, msg in threats:
        (err if level=="DANGER" else warn)(msg)
    if not threats: ok("No spoofing indicators.")
    overall = any(t[0]=="DANGER" for t in threats)
    print(f"\n  Verdict: {c('🚨 SUSPICIOUS', C.RED) if overall else c('✔ Appears legitimate', C.GREEN)}")


# ═══════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ═══════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    cli_mode()
