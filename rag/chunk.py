"""Turn man pages, rst docs, C source and plain text into (title, path, loc, body) chunks."""
import re

MAX = 2400


def split_long(title, path, loc, body, max_len=MAX):
    """Split a long body on line boundaries; each part keeps the title."""
    if len(body) <= max_len:
        return [(title, path, loc, body)]
    out, buf, n = [], [], 0
    for line in body.split("\n"):
        if n + len(line) > max_len and buf:
            out.append("\n".join(buf))
            buf, n = [], 0
        buf.append(line[:max_len])
        n += len(line) + 1
    if buf:
        out.append("\n".join(buf))
    return [(f"{title} (part {i + 1})" if len(out) > 1 else title, path, loc, b) for i, b in enumerate(out)]


# ---------- man pages (roff) ----------

_ESC = [(r"\\f(?:\[[^\]]*\]|\(..|.)", ""), (r"\\\(em", "—"), (r"\\\(en", "–"), (r"\\\(aq", "'"),
        (r"\\\(dq", '"'), (r"\\\(bu", "•"), (r"\\\[[^\]]*\]", ""), (r"\\\(..", ""), (r"\\-", "-"),
        (r"\\~", " "), (r"\\ ", " "), (r"\\&", ""), (r"\\e", "\\\\"), (r"\\c", ""), (r"\\%", ""),
        (r"\\[|^0:/,]", "")]
_ESC = [(re.compile(a), b) for a, b in _ESC]
_FONT = {"B", "I", "R", "BR", "BI", "IB", "IR", "RB", "RI", "SM", "SB", "MR", "UR", "MT"}
_DROP = {"nf", "fi", "EX", "EE", "RS", "RE", "in", "sp", "br", "ad", "na", "ne", "hy", "nh", "ft",
         "ps", "vs", "ll", "ta", "ce", "UE", "ME", "YS", "SY", "OP", "TS", "TE", "T{", "T}", "ti", "tr", "ds"}


def _unesc(s):
    for rx, rep in _ESC:
        s = rx.sub(rep, s)
    return s


def _args(s):
    return [a.strip('"') for a in re.findall(r'"[^"]*"|\S+', s)]


def roff_to_text(src):
    """Returns (name, section, [(heading, text)])."""
    name, sec, sections, head, buf = "", "", [], "", []
    for line in src.split("\n"):
        if line.startswith('.\\"') or line.startswith("'\\\"") or line == ".":
            continue
        if line.startswith(".") or line.startswith("'"):
            parts = line[1:].split(None, 1)
            if not parts:
                continue
            mac, rest = parts[0], (parts[1] if len(parts) > 1 else "")
            if mac == "TH":
                a = _args(rest)
                name, sec = (a + ["", ""])[:2]
            elif mac in ("SH", "SS"):
                if mac == "SH":
                    sections.append((head, "\n".join(buf).strip()))
                    head, buf = _unesc(" ".join(_args(rest))), []
                else:
                    buf.append("\n" + _unesc(" ".join(_args(rest))))
            elif mac in ("P", "PP", "LP", "TP", "IP", "HP", "TQ"):
                buf.append("")
                if mac == "IP" and rest:
                    buf.append(_unesc(_args(rest)[0]))
            elif mac in _FONT:
                a = _args(rest)
                buf.append(_unesc(("" if len(mac) == 2 else " ").join(a)))
            elif mac in _DROP:
                continue
            continue
        buf.append(_unesc(line))
    sections.append((head, "\n".join(buf).strip()))
    return name, sec, [(h, re.sub(r"\n{3,}", "\n\n", t)) for h, t in sections if t]


def man_chunks(src, path):
    name, sec, sections = roff_to_text(src)
    if not name:
        return []
    summary = next((t.replace("\n", " ") for h, t in sections if h == "NAME"), "")
    label = f"{name}({sec})"
    out = []
    for head, text in sections:
        if head in ("NAME", "LIBRARY", "COLOPHON", "SEE ALSO", "STANDARDS"):
            continue
        body = f"{label}: {summary}\n{head}\n{text}"
        out += split_long(f"{label} {head}", path, "", body)
    return out


# ---------- rst docs ----------

_UNDER = re.compile(r"^([=\-~^\"'`#*+])\1{2,}\s*$")


def rst_chunks(src, path):
    lines = src.split("\n")
    title, cur, buf, out = "", "", [], []
    start = 1

    def flush(end):
        body = "\n".join(buf).strip()
        if len(body) > 80:
            t = f"{title} — {cur}" if cur and cur != title else (title or path)
            out.extend(split_long(t, path, f"L{start}-{end}", body))

    i = 0
    while i < len(lines):
        ln = lines[i]
        if i + 1 < len(lines) and ln.strip() and not _UNDER.match(ln) and _UNDER.match(lines[i + 1]) \
                and len(lines[i + 1].strip()) >= len(ln.strip()) - 2:
            flush(i)
            buf, start = [], i + 1
            cur = ln.strip()
            if not title:
                title = cur
            buf.append(cur)
            i += 2
            continue
        buf.append(ln)
        i += 1
    flush(len(lines))
    return out


# ---------- C source ----------

_FN_START = re.compile(r"^[A-Za-z_][^;{}=]*\(")
_SYSCALL = re.compile(r"^(?:COMPAT_)?SYSCALL_DEFINE\d\((\w+)")
_NAME = re.compile(r"(\w+)\s*\(")
_DEF = re.compile(r"^\s*(?:#\s*define\s+(\w+)|(?:struct|union|enum)\s+(\w+)\s*\{|typedef\b.*?(\w+)\s*;)")


def _fn_name(sig):
    m = _SYSCALL.match(sig)
    if m:
        return f"SYSCALL_DEFINE {m.group(1)} sys_{m.group(1)}"
    names = [n for n in _NAME.findall(sig) if n not in ("__attribute__", "__releases", "__acquires", "__must_hold")]
    return names[0] if names else sig[:40]


def c_chunks(src, path, region_lines=60):
    lines = src.split("\n")
    out, region, rstart, i = [], [], 1, 0

    def flush_region(end):
        text = "\n".join(region)
        if len(text.strip()) < 120:
            return
        names = []
        for l in region:
            m = _DEF.match(l)
            if m:
                n = next(g for g in m.groups() if g)
                if n not in names:
                    names.append(n)
        t = f"{path} " + (" ".join(names[:12]) if names else "region")
        out.extend(split_long(t, path, f"L{rstart}-{end}", text))

    while i < len(lines):
        ln = lines[i]
        if _FN_START.match(ln) and not ln.startswith(("#", "static_assert", "EXPORT_SYMBOL", "module_", "late_initcall")):
            # look ahead for an opening brace on its own line (kernel style)
            j = i
            while j < len(lines) and j - i < 8 and lines[j] != "{" and not lines[j].rstrip().endswith(";"):
                j += 1
            if j < len(lines) and lines[j] == "{":
                k = j + 1
                while k < len(lines) and lines[k] != "}":
                    k += 1
                if k < len(lines) and k - i < 1500:
                    # pull the comment right above the function into the chunk
                    c = len(region)
                    while c > 0 and region[c - 1].strip().startswith(("/*", "*", "*/")):
                        c -= 1
                    doc = region[c:]
                    region = region[:c]
                    flush_region(i - len(doc))
                    region, rstart = [], k + 2
                    sig = " ".join(l.strip() for l in lines[i:j])
                    body = "\n".join(doc + lines[i:k + 1])
                    out.extend(split_long(_fn_name(sig), path, f"L{i + 1}-{k + 1}", body, 3000))
                    i = k + 1
                    continue
        region.append(ln)
        if len(region) >= region_lines and not ln.strip():
            flush_region(i + 1)
            region, rstart = [], i + 2
        i += 1
    flush_region(len(lines))
    return out


def text_chunks(src, path, lines_per=60):
    lines = src.split("\n")
    out = []
    for s in range(0, len(lines), lines_per):
        body = "\n".join(lines[s:s + lines_per]).strip()
        if body:
            out.extend(split_long(path, path, f"L{s + 1}-{min(len(lines), s + lines_per)}", body))
    return out
