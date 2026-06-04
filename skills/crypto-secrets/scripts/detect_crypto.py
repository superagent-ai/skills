#!/usr/bin/env python3
"""
crypto-secrets cryptographic detector.

This module is the deterministic Stage 1 crypto/JWT/TLS half of the skill. It
uses Python AST where it materially reduces false positives, then falls back to
language-aware line patterns. It does not execute target code.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from pathlib import Path


SECURITY_WORDS = re.compile(
    r"(?i)\b(password|passwd|pwd|secret|token|session|cookie|auth|jwt|sign|"
    r"signature|encrypt|decrypt|key|nonce|iv|csrf|reset|credential|api[_-]?key)\b"
)

CHECKSUM_WORDS = re.compile(r"(?i)\b(checksum|etag|digest|hashsum|fingerprint|git|cache[_-]?key)\b")
TEST_WORDS = re.compile(r"(?i)(^|/)(test|tests|spec|fixtures?|examples?|docs?)(/|$)|(_test|\.spec|\.test)\.")

LANG_BY_SUFFIX = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".go": "go",
    ".java": "java",
    ".kt": "kotlin",
    ".kts": "kotlin",
    ".rb": "ruby",
    ".php": "php",
    ".c": "c",
    ".h": "c",
    ".cc": "cpp",
    ".cpp": "cpp",
    ".cxx": "cpp",
    ".hpp": "cpp",
    ".rs": "rust",
    ".swift": "swift",
    ".m": "objc",
    ".mm": "objc",
    ".yml": "yaml",
    ".yaml": "yaml",
    ".json": "json",
    ".toml": "toml",
    ".env": "env",
}

COMMENT_PREFIXES = ("#", "//", "--", "*")
DOC_SUFFIXES = {".md", ".markdown", ".rst", ".txt"}
RULE_CATALOG_NAMES = {"crypto-checklist.yaml", "secrets-patterns.yaml"}


@dataclass(frozen=True)
class Rule:
    rule_id: str
    category: str
    title: str
    severity: str
    patterns: tuple[str, ...]
    languages: tuple[str, ...] = ()
    remediation: str = ""
    rationale: str = ""
    references: tuple[str, ...] = ()
    requires_security_context: bool = False
    ignore_checksum_context: bool = False


RULES: tuple[Rule, ...] = (
    Rule(
        "crypto-md5-password",
        "Hash",
        "MD5 used in a security-sensitive context",
        "P1",
        (r"\bmd5\s*\(", r"hashlib\.md5\s*\(", r"createHash\s*\(\s*['\"]md5['\"]", r"MessageDigest\.getInstance\s*\(\s*['\"]MD5['\"]"),
        remediation="Use Argon2id, bcrypt, or scrypt for passwords; use SHA-256/HMAC only for non-password integrity.",
        rationale="MD5 is fast and collision-prone; in password or token paths it enables cheap offline cracking or weak security decisions.",
        references=("https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html",),
        requires_security_context=True,
        ignore_checksum_context=True,
    ),
    Rule(
        "crypto-sha1-password",
        "Hash",
        "SHA1 used in a security-sensitive context",
        "P1",
        (r"\bsha1\s*\(", r"hashlib\.sha1\s*\(", r"createHash\s*\(\s*['\"]sha1['\"]", r"MessageDigest\.getInstance\s*\(\s*['\"]SHA-?1['\"]"),
        remediation="Use Argon2id, bcrypt, or scrypt for passwords; use SHA-256/HMAC only for non-password integrity.",
        rationale="SHA1 is deprecated and too fast for password hashing or security-sensitive decisions.",
        references=("https://www.nist.gov/news-events/news/2022/12/nist-retires-sha-1-cryptographic-algorithm",),
        requires_security_context=True,
        ignore_checksum_context=True,
    ),
    Rule(
        "crypto-ripemd160",
        "Hash",
        "RIPEMD160 used in security-sensitive code",
        "P2",
        (r"\bripemd160\b", r"\brmd160\b"),
        remediation="Use SHA-256/HMAC for integrity or Argon2id/bcrypt/scrypt for password storage.",
        rationale="RIPEMD160 is not a modern default for new application security decisions.",
        references=("https://cwe.mitre.org/data/definitions/327.html",),
        requires_security_context=True,
    ),
    Rule(
        "crypto-des",
        "Symmetric",
        "DES encryption",
        "P1",
        (r"\bDES\.new\b", r"createCipheriv\s*\(\s*['\"]des", r"Cipher\.getInstance\s*\(\s*['\"]DES(?:/|['\"])", r"\bdes-cbc\b"),
        remediation="Use AES-256-GCM or ChaCha20-Poly1305 with a fresh nonce per encryption.",
        rationale="DES has a 56-bit key and is brute-forceable.",
        references=("https://cwe.mitre.org/data/definitions/327.html",),
    ),
    Rule(
        "crypto-3des",
        "Symmetric",
        "3DES encryption",
        "P2",
        (r"\bDES3\b", r"\bTripleDES\b", r"\bDESede\b", r"des-ede3"),
        remediation="Migrate to AES-GCM or ChaCha20-Poly1305; keep legacy decrypt-only paths isolated.",
        rationale="3DES is deprecated and has a small block size.",
        references=("https://csrc.nist.gov/publications/detail/sp/800-131a/rev-2/final",),
    ),
    Rule(
        "crypto-rc4",
        "Symmetric",
        "RC4 stream cipher",
        "P1",
        (r"\bARC4\b", r"\bRC4\b", r"\barcfour\b"),
        remediation="Use AES-GCM or ChaCha20-Poly1305.",
        rationale="RC4 is cryptographically broken and must not protect traffic or stored data.",
        references=("https://www.rfc-editor.org/rfc/rfc7465",),
    ),
    Rule(
        "crypto-aes-ecb",
        "Symmetric",
        "AES ECB mode",
        "P1",
        (r"AES\.MODE_ECB", r"aes-\d+-ecb", r"AES/ECB"),
        remediation="Use an AEAD mode such as AES-GCM or ChaCha20-Poly1305.",
        rationale="ECB leaks plaintext structure and is not semantically secure.",
        references=("https://cwe.mitre.org/data/definitions/327.html",),
    ),
    Rule(
        "crypto-cbc-without-auth",
        "Symmetric",
        "CBC or CTR encryption without visible authentication",
        "P2",
        (r"AES\.MODE_CBC", r"AES\.MODE_CTR", r"aes-\d+-(?:cbc|ctr)", r"AES/(?:CBC|CTR)"),
        remediation="Prefer AES-GCM/ChaCha20-Poly1305, or add encrypt-then-MAC with HMAC-SHA256.",
        rationale="CBC/CTR are malleable without a separate authentication step.",
        references=("https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html",),
    ),
    Rule(
        "crypto-static-iv",
        "Symmetric",
        "Hardcoded IV or nonce",
        "P1",
        (r"\b(?:iv|nonce)\b\s*[:=]\s*(?:b?['\"][0-9A-Za-z+/=]{8,}['\"]|\[[0-9,\s]+\])", r"new\s+IvParameterSpec\s*\(\s*['\"]"),
        remediation="Generate a fresh cryptographically random IV/nonce for every encryption operation.",
        rationale="IV/nonce reuse can reveal plaintext or break AEAD security.",
        references=("https://cwe.mitre.org/data/definitions/329.html",),
    ),
    Rule(
        "crypto-rsa-pkcs1v15",
        "Asymmetric",
        "RSA PKCS#1 v1.5 padding",
        "P2",
        (r"PKCS1_v1_5", r"RSA_PKCS1_PADDING", r"RSA/ECB/PKCS1Padding", r"rsa\.PKCS1v15"),
        remediation="Use RSA-OAEP for encryption and RSA-PSS for signatures.",
        rationale="PKCS#1 v1.5 padding has safer modern replacements and is easy to misuse.",
        references=("https://cwe.mitre.org/data/definitions/780.html",),
    ),
    Rule(
        "crypto-rsa-weak-key",
        "Asymmetric",
        "RSA key smaller than 2048 bits",
        "P1",
        (r"key_size\s*=\s*1024", r"GenerateKey\s*\([^,\)]*1024", r"rsa:1024"),
        remediation="Use RSA 2048/3072 or Ed25519 where supported.",
        rationale="RSA keys below 2048 bits do not meet modern security baselines.",
        references=("https://csrc.nist.gov/publications/detail/sp/800-131a/rev-2/final",),
    ),
    Rule(
        "crypto-ec-weak-curve",
        "Asymmetric",
        "Weak or obsolete elliptic curve",
        "P2",
        (r"secp192", r"prime192", r"sect163", r"secp224"),
        remediation="Use P-256, P-384, X25519, or Ed25519 depending on the protocol.",
        rationale="Obsolete curves should not be introduced for new signatures or key exchange.",
        references=("https://cwe.mitre.org/data/definitions/327.html",),
    ),
    Rule(
        "crypto-python-random-token",
        "Random",
        "Python random used for security-sensitive value",
        "P1",
        (r"\brandom\.(?:random|choice|choices|randint|randrange|sample)\s*\(",),
        ("python",),
        remediation="Use the secrets module, such as secrets.token_urlsafe() or secrets.token_hex().",
        rationale="Python's random module is predictable and unsuitable for tokens, nonces, or secrets.",
        references=("https://docs.python.org/3/library/secrets.html",),
        requires_security_context=True,
    ),
    Rule(
        "crypto-js-math-random-token",
        "Random",
        "Math.random used for security-sensitive value",
        "P1",
        (r"\bMath\.random\s*\(",),
        ("javascript", "typescript"),
        remediation="Use crypto.randomBytes() in Node or crypto.getRandomValues() in browsers.",
        rationale="Math.random is predictable and unsuitable for tokens, sessions, nonces, or secrets.",
        references=("https://developer.mozilla.org/en-US/docs/Web/API/Crypto/getRandomValues",),
        requires_security_context=True,
    ),
    Rule(
        "crypto-c-rand-token",
        "Random",
        "C rand/srand used for security-sensitive value",
        "P1",
        (r"\brand\s*\(", r"\bsrand\s*\("),
        ("c", "cpp"),
        remediation="Use getrandom(), arc4random_buf(), or libsodium randombytes_buf().",
        rationale="rand/srand are predictable and unsuitable for security-sensitive values.",
        references=("https://cwe.mitre.org/data/definitions/338.html",),
        requires_security_context=True,
    ),
    Rule(
        "crypto-java-random-token",
        "Random",
        "java.util.Random used for security-sensitive value",
        "P1",
        (r"\bnew\s+Random\s*\(", r"\bjava\.util\.Random\b"),
        ("java", "kotlin"),
        remediation="Use java.security.SecureRandom for security-sensitive randomness.",
        rationale="java.util.Random is predictable and unsuitable for tokens or keys.",
        references=("https://cwe.mitre.org/data/definitions/338.html",),
        requires_security_context=True,
    ),
    Rule(
        "crypto-pbkdf2-low-iterations",
        "KDF",
        "PBKDF2 iteration count too low",
        "P2",
        (r"pbkdf2[^,\n]*(?:,\s*|\(|iterations\s*[:=]\s*)[1-9][0-9]{0,4}\b", r"PBKDF2WithHmacSHA.*[\"'],\s*[1-9][0-9]{0,4}\b"),
        remediation="Use Argon2id/bcrypt/scrypt, or PBKDF2-HMAC-SHA256 with a current high iteration count.",
        rationale="Low PBKDF2 iteration counts are cheap to brute-force offline.",
        references=("https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html",),
    ),
    Rule(
        "crypto-bcrypt-low-cost",
        "KDF",
        "Bcrypt cost too low",
        "P2",
        (r"bcrypt[^,\n]*(?:rounds|saltRounds|cost)\s*[:=]\s*[1-9]\b", r"BCrypt\.gensalt\s*\(\s*[1-9]\s*\)"),
        remediation="Use bcrypt cost 12 or higher, or Argon2id with tuned memory/time parameters.",
        rationale="Low bcrypt work factors are too cheap for modern password storage.",
        references=("https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html",),
    ),
    Rule(
        "crypto-hardcoded-salt",
        "KDF",
        "Hardcoded password salt",
        "P1",
        (r"\bSALT\b\s*=\s*['\"][^'\"]{4,}['\"]", r"\bsalt\b\s*[:=]\s*['\"][^'\"]{4,}['\"]"),
        remediation="Generate a unique random salt per password and store it with the password hash.",
        rationale="Static salts let attackers amortize cracking across users and deployments.",
        references=("https://cwe.mitre.org/data/definitions/759.html",),
        requires_security_context=True,
    ),
    Rule(
        "crypto-tls-verify-disabled",
        "TLS",
        "TLS certificate verification disabled",
        "P1",
        (r"verify\s*=\s*False", r"rejectUnauthorized\s*:\s*false", r"InsecureSkipVerify\s*:\s*true", r"CERT_NONE", r"TrustAll", r"check_hostname\s*=\s*False"),
        remediation="Enable certificate verification and configure a trusted CA bundle for private PKI.",
        rationale="Disabling TLS verification enables man-in-the-middle attacks.",
        references=("https://cwe.mitre.org/data/definitions/295.html",),
    ),
    Rule(
        "crypto-tls-old-version",
        "TLS",
        "SSL or old TLS version enabled",
        "P1",
        (r"\bSSLv[23]\b", r"\bTLSv1(?:\.0|\.1)?\b(?!\.2|\.3)", r"PROTOCOL_TLSv1(?:_1)?\b"),
        remediation="Require TLS 1.2 minimum and prefer TLS 1.3 where supported.",
        rationale="SSLv2, SSLv3, TLS 1.0, and TLS 1.1 are deprecated.",
        references=("https://www.rfc-editor.org/rfc/rfc8996",),
    ),
    Rule(
        "crypto-cert-self-signed-prod",
        "TLS",
        "Self-signed certificate outside obvious tests",
        "P2",
        (r"self[_-]?signed",),
        remediation="Use a public CA or internal CA with explicit trust distribution.",
        rationale="Self-signed production certificates often hide trust bypasses.",
        references=("https://cwe.mitre.org/data/definitions/295.html",),
    ),
    Rule(
        "crypto-cert-weak-key",
        "TLS",
        "Weak certificate key size",
        "P2",
        (r"rsa:1024", r"key[_-]?size\s*[:=]\s*1024"),
        remediation="Use RSA 2048/3072 or a modern EC key.",
        rationale="Weak certificate key sizes do not meet modern security baselines.",
        references=("https://csrc.nist.gov/publications/detail/sp/800-131a/rev-2/final",),
    ),
    Rule(
        "crypto-jwt-alg-none",
        "JWT",
        "JWT alg none accepted or generated",
        "P1",
        (r"alg(?:orithm)?s?\s*[:=]\s*\[?\s*['\"]none['\"]", r"verify_signature\s*[:=]\s*False", r"alg\s*[:=]\s*['\"]none['\"]"),
        remediation="Require signature verification and pin explicit allowed algorithms.",
        rationale="Accepting unsigned JWTs can allow token forgery.",
        references=("https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html",),
    ),
    Rule(
        "crypto-jwt-hardcoded-secret",
        "JWT",
        "Hardcoded JWT signing secret",
        "P0",
        (r"\bJWT_SECRET\b\s*[:=]\s*['\"][^'\"]{8,}['\"]", r"\bjwt[_-]?secret\b\s*[:=]\s*['\"][^'\"]{8,}['\"]", r"jwt\.(?:sign|encode)\s*\([^,\n]+,\s*['\"][^'\"]{8,}['\"]"),
        remediation="Load signing keys from a secret manager or environment; rotate the exposed key and invalidate affected tokens.",
        rationale="Hardcoded signing secrets can allow token forgery if source is exposed.",
        references=("https://cwe.mitre.org/data/definitions/798.html",),
    ),
    Rule(
        "crypto-pickle-loads",
        "Serialization",
        "Python pickle deserialization",
        "P1",
        (r"\bpickle\.loads?\s*\(",),
        ("python",),
        remediation="Use JSON or a schema-validated format; never unpickle attacker-controlled data.",
        rationale="Pickle deserialization can execute code when input is attacker-controlled.",
        references=("https://docs.python.org/3/library/pickle.html",),
    ),
    Rule(
        "crypto-yaml-unsafe-load",
        "Serialization",
        "Unsafe YAML load",
        "P1",
        (r"\byaml\.load\s*\(",),
        ("python",),
        remediation="Use yaml.safe_load() or yaml.load(..., Loader=yaml.SafeLoader).",
        rationale="yaml.load without a safe loader can instantiate arbitrary objects.",
        references=("https://pyyaml.org/wiki/PyYAMLDocumentation",),
    ),
)


def language_for(path: Path) -> str:
    if path.name in {".env", ".env.local", ".env.production", ".env.development"}:
        return "env"
    return LANG_BY_SUFFIX.get(path.suffix.lower(), "text")


def scan_file(path: Path, rel: str, text: str) -> list[dict]:
    """Return crypto/JWT/TLS findings for a decoded text file."""
    if path.suffix.lower() in DOC_SUFFIXES or path.name in RULE_CATALOG_NAMES:
        return []

    lang = language_for(path)
    lines = text.splitlines()
    findings: list[dict] = []
    seen: set[tuple[str, int]] = set()

    if lang == "python":
        for finding in _scan_python_ast(rel, lines, text):
            seen.add((finding["rule_id"], finding["line"]))
            findings.append(finding)

    for rule in RULES:
        if rule.languages and lang not in rule.languages:
            continue
        for i, line in enumerate(lines, start=1):
            if (rule.rule_id, i) in seen:
                continue
            if _is_comment_only(line) or _is_rule_metadata_line(line):
                continue
            if _line_matches_rule(line, rule) and _context_allows(rule, rel, lines, i):
                findings.append(_finding(rule, rel, i, line))
                seen.add((rule.rule_id, i))

    findings.extend(_scan_jwt_missing_exp(rel, lines))
    return _dedupe(findings)


def _scan_python_ast(rel: str, lines: list[str], text: str) -> list[dict]:
    out: list[dict] = []
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return out

    imports: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports[alias.asname or alias.name] = alias.name
        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            for alias in node.names:
                imports[alias.asname or alias.name] = f"{mod}.{alias.name}".strip(".")

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = _call_name(node.func, imports)
        line = lines[node.lineno - 1] if 0 < node.lineno <= len(lines) else ""
        window = _window(lines, node.lineno)
        if name in {"hashlib.md5", "md5"} and SECURITY_WORDS.search(window) and not CHECKSUM_WORDS.search(window):
            out.append(_finding(_rule_by_id("crypto-md5-password"), rel, node.lineno, line))
        elif name in {"hashlib.sha1", "sha1"} and SECURITY_WORDS.search(window) and not CHECKSUM_WORDS.search(window):
            out.append(_finding(_rule_by_id("crypto-sha1-password"), rel, node.lineno, line))
        elif name in {"random.random", "random.choice", "random.choices", "random.randint", "random.randrange"} and SECURITY_WORDS.search(window):
            out.append(_finding(_rule_by_id("crypto-python-random-token"), rel, node.lineno, line))
        elif name in {"pickle.load", "pickle.loads"}:
            out.append(_finding(_rule_by_id("crypto-pickle-loads"), rel, node.lineno, line))
        elif name == "yaml.load" and not _yaml_call_has_safe_loader(node):
            out.append(_finding(_rule_by_id("crypto-yaml-unsafe-load"), rel, node.lineno, line))
    return _dedupe(out)


def _call_name(func: ast.AST, imports: dict[str, str]) -> str:
    if isinstance(func, ast.Name):
        return imports.get(func.id, func.id)
    if isinstance(func, ast.Attribute):
        base = _call_name(func.value, imports)
        return f"{base}.{func.attr}" if base else func.attr
    return ""


def _yaml_call_has_safe_loader(node: ast.Call) -> bool:
    for kw in node.keywords:
        if kw.arg == "Loader":
            value = ast.unparse(kw.value) if hasattr(ast, "unparse") else ""
            if "SafeLoader" in value:
                return True
    return False


def _scan_jwt_missing_exp(rel: str, lines: list[str]) -> list[dict]:
    rule = Rule(
        "crypto-jwt-no-exp",
        "JWT",
        "JWT issued without expiration",
        "P2",
        (),
        remediation="Include a short-lived exp claim and validate it on decode.",
        rationale="Tokens without exp remain valid until key rotation or custom revocation.",
        references=("https://datatracker.ietf.org/doc/html/rfc7519",),
    )
    out: list[dict] = []
    for i, line in enumerate(lines, start=1):
        if _is_comment_only(line):
            continue
        if re.search(r"\b(jwt\.(?:encode|sign)|jwtSign|jsonwebtoken\.sign)\s*\(", line):
            window = _window(lines, i, radius=4)
            if not re.search(r"['\"]exp['\"]|\bexp\s*[:=]", window):
                out.append(_finding(rule, rel, i, line))
    return out


def _line_matches_rule(line: str, rule: Rule) -> bool:
    return any(re.search(pattern, line, re.IGNORECASE) for pattern in rule.patterns)


def _context_allows(rule: Rule, rel: str, lines: list[str], line_no: int) -> bool:
    window = _window(lines, line_no)
    if TEST_WORDS.search(rel) and rule.severity != "P0":
        return False
    if rule.ignore_checksum_context and CHECKSUM_WORDS.search(window):
        return False
    if rule.requires_security_context and not SECURITY_WORDS.search(window):
        return False
    if rule.rule_id == "crypto-cbc-without-auth" and re.search(r"\b(hmac|mac|authenticate|auth_tag|tag|sign|verify)\b", window, re.I):
        return False
    if rule.rule_id == "crypto-yaml-unsafe-load" and re.search(r"SafeLoader|safe_load", window):
        return False
    if rule.rule_id == "crypto-cert-self-signed-prod" and re.search(r"(?i)\b(localhost|local[-_ ]?dev|test|fixture|example)\b", window + rel):
        return False
    return True


def _finding(rule: Rule, rel: str, line_no: int, line: str) -> dict:
    return {
        "rule_id": rule.rule_id,
        "severity": rule.severity,
        "category": rule.category,
        "title": rule.title,
        "file": rel,
        "line": line_no,
        "snippet": line.strip()[:220],
        "confidence": 0.85 if rule.severity in {"P0", "P1"} else 0.75,
        "remediation": rule.remediation,
        "rationale": rule.rationale,
        "references": list(rule.references),
        "kind": "crypto",
        "rotation_required": rule.rule_id == "crypto-jwt-hardcoded-secret",
    }


def _rule_by_id(rule_id: str) -> Rule:
    for rule in RULES:
        if rule.rule_id == rule_id:
            return rule
    raise KeyError(rule_id)


def _is_comment_only(line: str) -> bool:
    stripped = line.strip()
    return not stripped or stripped.startswith(COMMENT_PREFIXES)


def _is_rule_metadata_line(line: str) -> bool:
    stripped = line.strip()
    if stripped.startswith(("r\"", "r'", "\"", "'", "(r\"", "(r'", "(\"", "('")):
        return True
    return stripped.startswith((
        "Rule(",
        "rationale=",
        "remediation=",
        "references=",
        "description:",
        "title:",
        "bad_patterns:",
        "good_patterns:",
    ))


def _window(lines: list[str], line_no: int, radius: int = 3) -> str:
    start = max(0, line_no - radius - 1)
    end = min(len(lines), line_no + radius)
    return "\n".join(lines[start:end])


def _dedupe(findings: list[dict]) -> list[dict]:
    out: list[dict] = []
    seen: set[tuple[str, str, int, str]] = set()
    for finding in findings:
        key = (finding["rule_id"], finding["file"], finding["line"], finding["snippet"])
        if key in seen:
            continue
        seen.add(key)
        out.append(finding)
    return out
