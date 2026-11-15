"""Redact secrets and personal data from logs and configs before indexing.

Order matters: multi-line blocks first, then structured key/value secrets,
then generic tokens, then network identifiers.
"""
import re

R = "[REDACTED]"

_SENSITIVE_KEY = (r"(?:pass(?:word|wd|phrase)?|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|"
                  r"private[_-]?key|client[_-]?secret|auth|credential|cred|salt|session|cookie|signature|sig|dsn|"
                  r"database_url|db_url|webhook)")

_RULES = [
    # PEM / key blocks
    (re.compile(r"-----BEGIN [A-Z0-9 ]*(?:PRIVATE KEY|CERTIFICATE|KEY)[A-Z ]*-----.*?-----END [A-Z0-9 ]+-----", re.S),
     "[REDACTED-PEM]"),
    (re.compile(r"\bssh-(?:rsa|ed25519|dss)\s+[A-Za-z0-9+/=]{20,}(?:\s+\S+)?"), "[REDACTED-SSH-KEY]"),
    (re.compile(r"\becdsa-sha2-nistp\d+\s+[A-Za-z0-9+/=]{20,}(?:\s+\S+)?"), "[REDACTED-SSH-KEY]"),
    # HTTP headers carrying credentials or identity
    (re.compile(r"(?im)^(\s*(?:authorization|proxy-authorization|cookie|set-cookie|x-api-key|x-auth-token)\s*:\s*).*$"),
     r"\1" + R),
    (re.compile(r"(?i)\b(bearer|basic|token)\s+[A-Za-z0-9._~+/=-]{8,}"), r"\1 " + R),
    # nginx directives that embed credentials
    (re.compile(r"(?im)^(\s*(?:proxy_set_header|add_header|more_set_headers)\s+(?:Authorization|Cookie|X-Api-Key)\s+)[^;]+;"),
     r"\1" + R + ";"),
    # key=value / key: value / KEY="value" with a sensitive key name (env lines, systemd Environment=, json)
    (re.compile(r"(?i)([\"']?[A-Za-z0-9_.-]*" + _SENSITIVE_KEY + r"[A-Za-z0-9_.-]*[\"']?\s*[=:]\s*)"
                r"(\"[^\"\n]*\"|'[^'\n]*'|[^\s,;&\"'}]+)"), r"\1" + R),
    # same, inside URL query strings
    (re.compile(r"(?i)([?&][A-Za-z0-9_.-]*(?:" + _SENSITIVE_KEY + r"|code|key|email|state|ticket|jwt)[A-Za-z0-9_.-]*=)[^&\s\"]+"),
     r"\1" + R),
    # credentials in URLs  scheme://user:pass@host
    (re.compile(r"\b([a-z][a-z0-9+.-]*://)[^/\s:@]+:[^/\s@]+@"), r"\1" + R + "@"),
    # well-known token formats
    (re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"), "[REDACTED-JWT]"),
    (re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})"), "[REDACTED-TOKEN]"),
    (re.compile(r"\b(?:xai|sk|pk|rk)[-_](?:live_|test_|proj-|ant-)?[A-Za-z0-9_-]{16,}"), "[REDACTED-TOKEN]"),
    (re.compile(r"\bwhsec_[A-Za-z0-9]{16,}"), "[REDACTED-TOKEN]"),
    (re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"), "[REDACTED-TOKEN]"),
    (re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"), "[REDACTED-TOKEN]"),
    (re.compile(r"\bAIza[0-9A-Za-z_-]{30,}"), "[REDACTED-TOKEN]"),
    # emails
    (re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), "[EMAIL]"),
    # IPv6 (full, compressed, with optional zone) before IPv4
    (re.compile(r"(?i)(?<![\w:.])(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}(?![0-9a-f:])"), "[IPV6]"),
    (re.compile(r"(?i)(?<![\w:.])(?:(?:[0-9a-f]{1,4}:){1,7}:|(?:[0-9a-f]{1,4}:){1,6}(?::[0-9a-f]{1,4}){1,6}"
                r"|:(?::[0-9a-f]{1,4}){1,7})(?:%\w+)?(?![0-9a-f:])"), "[IPV6]"),
    # IPv4 (optionally with /cidr or :port kept outside)
    (re.compile(r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\d.])"), "[IP]"),
    # MAC addresses
    (re.compile(r"(?i)\b(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\b"), "[MAC]"),
    # long hex / base64 blobs (hashes, session ids, raw keys)
    (re.compile(r"\b[A-Fa-f0-9]{32,}\b"), "[REDACTED-HEX]"),
    (re.compile(r"(?<![A-Za-z0-9+/_-])(?=[A-Za-z0-9+/_-]*\d)(?=[A-Za-z0-9+/_-]*[A-Z])(?=[A-Za-z0-9+/_-]*[a-z])"
                r"[A-Za-z0-9+/_-]{32,}={0,2}(?![A-Za-z0-9+/_-])"), "[REDACTED-BLOB]"),
]

# nginx "combined" log: ... "request" status bytes "referer" "user-agent" [extra]
_ACCESS = re.compile(r'^(.*?"[^"]*"\s+\d{3}\s+\S+\s+)"([^"]*)"\s+"([^"]*)"(.*)$')
_BOT = re.compile(r"(?i)bot|crawl|spider|slurp|curl|wget|python|go-http|okhttp|axios|node|java/|libwww|scan|httpclient|headless|monitor")


def classify_ua(ua):
    if not ua or ua == "-":
        return "-"
    if _BOT.search(ua):
        m = re.search(r"(?i)([a-z0-9_.-]*(?:bot|crawler|spider|curl|wget|python-requests|go-http-client|okhttp|axios|headless\w*))", ua)
        return "UA:bot(" + (m.group(1)[:32] if m else "other") + ")"
    if re.search(r"(?i)iphone|android|mobile", ua):
        return "UA:mobile-browser"
    if re.search(r"(?i)mozilla|chrome|safari|firefox|edg/", ua):
        return "UA:desktop-browser"
    return "UA:other"


def _access_line(line):
    m = _ACCESS.match(line)
    if not m:
        return line
    head, referer, ua, tail = m.groups()
    referer = referer.split("?", 1)[0] if referer != "-" else referer
    return f'{head}"{referer}" "{classify_ua(ua)}"{tail}'


def redact(text, access_log=False):
    if access_log:
        text = "\n".join(_access_line(l) for l in text.split("\n"))
    for rx, rep in _RULES:
        text = rx.sub(rep, text)
    return text


# Files that must never be read, let alone indexed.
_DENY = re.compile(r"(?i)(\.env(\.|$)|/\.env|\.pem$|\.key$|\.crt$|\.p12$|\.pfx$|\.jks$|id_rsa|id_ed25519|"
                   r"htpasswd|/letsencrypt/|/ssl/private|secret|credential|password|token|shadow|gbk-composer\.env)")


def path_allowed(path):
    return not _DENY.search(path)
