"""Snapshots of interesting /proc, /sys and /etc files, redacted, with pointers to their docs.

  python3 -m rag.snapshot --local samples/sys_snapshot.json          # public sample (run on the box)
  python3 -m rag.snapshot --ssh root@HOST /tmp/snap.json             # inspect what prod would give

collect_prod.py calls collect(run, public=False) to add the same set to the admin corpus.
All reads go through one shell script; globs are listed first and filtered with
redact.path_allowed, so denied files (shadow, sudoers, keys, *.env, ...) are never opened.
"""
import argparse
import json
import re
import shlex
import sys

from rag.redact import path_allowed, redact

PROC = "Documentation/filesystems/proc.rst"


def F(path, docs, xf=None, lines=None, public=True):
    """public=False: admin (prod) snapshot only; these files describe the host's own setup."""
    return {"kind": "file", "path": path, "docs": docs, "xf": xf, "lines": lines, "public": public}


def T(name, glob, docs, prefix):
    """A directory of one-value files rendered as `key = value` lines (sysctl style)."""
    return {"kind": "tree", "path": name, "glob": glob, "docs": docs, "prefix": prefix}


SPECS = [
    F("/proc/meminfo", ["man5/proc_meminfo.5", PROC]),
    F("/proc/cpuinfo", ["man5/proc_cpuinfo.5", "Documentation/arch/x86/cpuinfo.rst"], "first_block"),
    F("/proc/stat", ["man5/proc_stat.5", PROC]),
    F("/proc/vmstat", ["man5/proc_vmstat.5", PROC]),
    F("/proc/loadavg", ["man5/proc_loadavg.5"]),
    F("/proc/uptime", ["man5/proc_uptime.5"]),
    F("/proc/version", ["man5/proc_version.5"]),
    F("/proc/cmdline", ["man5/proc_cmdline.5", "Documentation/admin-guide/kernel-parameters.rst"], public=False),
    F("/proc/filesystems", ["man5/proc_filesystems.5", "man5/filesystems.5"]),
    F("/proc/mounts", ["man5/proc_mounts.5", "man5/proc_pid_mounts.5"], public=False),
    F("/proc/swaps", ["man5/proc_swaps.5"]),
    F("/proc/partitions", ["man5/proc_partitions.5"]),
    F("/proc/diskstats", ["man5/proc_diskstats.5", "Documentation/admin-guide/iostats.rst"]),
    F("/proc/interrupts", ["man5/proc_interrupts.5", PROC], lines=25),
    F("/proc/softirqs", [PROC]),
    F("/proc/buddyinfo", ["man5/proc_buddyinfo.5", PROC]),
    F("/proc/zoneinfo", ["man5/proc_zoneinfo.5", PROC], lines=120),
    F("/proc/slabinfo", ["man5/proc_slabinfo.5"], lines=40),
    F("/proc/pressure/cpu", ["Documentation/accounting/psi.rst"]),
    F("/proc/pressure/memory", ["Documentation/accounting/psi.rst"]),
    F("/proc/pressure/io", ["Documentation/accounting/psi.rst"]),
    F("/proc/pressure/irq", ["Documentation/accounting/psi.rst"]),
    T("/proc/sys/kernel", "/proc/sys/kernel/*", ["man5/proc_sys_kernel.5", "Documentation/admin-guide/sysctl/kernel.rst"], "kernel."),
    T("/proc/sys/vm", "/proc/sys/vm/*", ["man5/proc_sys_vm.5", "Documentation/admin-guide/sysctl/vm.rst"], "vm."),
    T("/proc/sys/net/core", "/proc/sys/net/core/*", ["man5/proc_sys_net.5", "Documentation/admin-guide/sysctl/net.rst"], "net.core."),
    T("/proc/sys/net/ipv4", "/proc/sys/net/ipv4/*", ["man5/proc_sys_net_ipv4.5", "Documentation/networking/ip-sysctl.rst"], "net.ipv4."),
    T("/proc/sys/fs", "/proc/sys/fs/*", ["man5/proc_sys_fs.5", "Documentation/admin-guide/sysctl/fs.rst"], "fs."),
    F("/proc/self/status", ["man5/proc_pid_status.5"]),
    F("/proc/self/limits", ["man5/proc_pid_limits.5", "man2/getrlimit.2"]),
    F("/proc/self/mountinfo", ["man5/proc_pid_mountinfo.5"], lines=40, public=False),
    F("/proc/self/cgroup", ["man5/proc_pid_cgroup.5", "man7/cgroups.7"]),
    F("/proc/net/dev", ["man5/proc_net.5"]),
    F("/proc/net/tcp", ["man5/proc_net.5", "Documentation/networking/proc_net_tcp.rst"], "net_tcp"),
    F("/proc/net/sockstat", ["man5/proc_net.5"]),
    F("/proc/net/snmp", ["man5/proc_net.5"]),
    T("/sys/fs/cgroup (cgroup v2 root)", "/sys/fs/cgroup/{cgroup.controllers,cgroup.subtree_control,cgroup.stat,"
      "cgroup.max.depth,cpu.stat,cpu.pressure,memory.pressure,io.pressure}", ["Documentation/admin-guide/cgroup-v2.rst",
                                                                               "man7/cgroups.7"], ""),
    T("/sys/block/<disk>/queue", "/sys/block/*/queue/{scheduler,nr_requests,rotational,read_ahead_kb,max_sectors_kb,"
      "logical_block_size,physical_block_size,discard_max_bytes,write_cache}", ["Documentation/ABI/stable/sysfs-block"], ""),
    T("/sys/devices/system/cpu", "/sys/devices/system/cpu/{online,possible,present,smt/active,cpu0/cpufreq/scaling_governor,"
      "cpu0/cpufreq/scaling_cur_freq,cpu0/cpufreq/cpuinfo_max_freq,cpu0/cpufreq/scaling_driver}",
      ["Documentation/admin-guide/cputopology.rst", "Documentation/admin-guide/pm/cpufreq.rst"], ""),
    T("/sys/kernel/mm/transparent_hugepage", "/sys/kernel/mm/transparent_hugepage/{enabled,defrag,shmem_enabled}",
      ["Documentation/admin-guide/mm/transhuge.rst"], ""),
    F("/etc/os-release", []),
    F("/etc/fstab", ["man5/proc_mounts.5"]),
    F("/etc/passwd", ["man5/passwd.5"], "passwd"),
    F("/etc/group", ["man5/group.5"], "group"),
    F("/etc/nsswitch.conf", ["man5/nsswitch.conf.5"]),
    F("/etc/hosts", ["man5/hosts.5"]),
    F("/etc/services", ["man5/services.5"], lines=80),
    F("/etc/protocols", ["man5/protocols.5"]),
    F("/etc/shells", ["man5/shells.5"]),
    F("/etc/login.defs", []),
    F("/etc/security/limits.conf", ["man2/getrlimit.2"]),
    F("/etc/sysctl.conf", ["man5/proc_sys.5"]),
    F("/etc/sysctl.d/*", ["man5/proc_sys.5"]),
    F("/etc/crontab", []),
    F("/etc/cron.d/*", []),
    F("/etc/logrotate.conf", []),
    F("/etc/ld.so.conf", ["man8/ld.so.8", "man8/ldconfig.8"]),
    F("/etc/ld.so.conf.d/*", ["man8/ld.so.8", "man8/ldconfig.8"]),
    F("/etc/resolv.conf", ["man5/resolv.conf.5"]),
]

PUBLIC_DROP = re.compile(r"^kernel\.(hostname|domainname)\b|^kernel\.random\.", re.M)
MAX_BYTES = 65536


# ---- transforms (pure functions, unit tested) ----

def first_block(text):
    return text.split("\n\n", 1)[0]


def _system_id(v, limit):
    return v.isdigit() and (int(v) < limit or int(v) == 65534)


def keep_system_passwd(text, limit=1000):
    """System accounts only (uid < limit, or nobody); humans are dropped."""
    out = []
    for line in text.splitlines():
        f = line.split(":")
        if len(f) >= 7 and _system_id(f[2], limit):
            out.append(line)
    return "\n".join(out)


def keep_system_group(text, limit=1000):
    """System groups only, member lists emptied (they name people)."""
    out = []
    for line in text.splitlines():
        f = line.split(":")
        if len(f) >= 4 and _system_id(f[2], limit):
            out.append(":".join(f[:3]) + ":")
    return "\n".join(out)


def net_tcp(text):
    """Header + 8 sockets; hex IPv4/IPv6 addresses masked, ports kept."""
    lines = text.splitlines()[:9]
    return "\n".join(re.sub(r"\b(?:[0-9A-F]{8}|[0-9A-F]{32}):", "[IPHEX]:", l) for l in lines)


XF = {"first_block": first_block, "passwd": keep_system_passwd, "group": keep_system_group, "net_tcp": net_tcp}


def strip_comments(text):
    return "\n".join(l for l in text.splitlines() if l.strip() and not l.lstrip().startswith("#"))


# ---- collection ----

def _list_script(specs):
    parts = []
    for i, s in enumerate(specs):
        g = s["glob"] if s["kind"] == "tree" else s["path"]
        if "*" in g or "{" in g:
            parts.append(f'for f in {g}; do [ -f "$f" ] && echo "{i} $f"; done')
        else:
            parts.append(f'[ -f {shlex.quote(g)} ] && echo "{i} {g}"')
    return "\n".join(parts)


def _read_script(paths):
    return "\n".join(f"echo '@@@F {p}'; timeout 3 head -c {MAX_BYTES} -- {shlex.quote(p)} 2>/dev/null; echo"
                     for p in paths)


def _parse(out):
    files, cur = {}, None
    for line in out.split("\n"):
        if line.startswith("@@@F "):
            cur = line[5:]
            files[cur] = []
        elif cur is not None:
            files[cur].append(line)
    return {k: "\n".join(v).rstrip("\n") for k, v in files.items()}


def collect(run, public=True, specs=SPECS, read_file=None):
    """run(cmd) -> stdout. Returns [{path, title, docs, text}] already transformed and redacted.
    If read_file(path) is given, each listed path is read through it after path_allowed (no shell read)."""
    if public:
        specs = [s for s in specs if s.get("public", True)]
    listed = {}
    for line in run("bash -c " + shlex.quote(_list_script(specs))).splitlines():
        i, _, p = line.partition(" ")
        if i.isdigit() and p:
            listed.setdefault(int(i), []).append(p)
    allowed, claimed = {}, set()
    for i in sorted(listed):  # a file belongs to the first spec that lists it
        allowed[i] = [p for p in listed[i] if p not in claimed and path_allowed(p)
                      and not re.search(r"\.(bak|old|orig|dpkg-\w+)$|~$", p)]
        claimed.update(allowed[i])
    # one block device only, skipping loop/ram devices
    for i, s in enumerate(specs):
        if s["path"].startswith("/sys/block/") and allowed.get(i):
            disks = sorted({p.split("/")[3] for p in allowed[i]})
            disk = next((d for d in disks if not d.startswith(("loop", "ram", "zram"))), disks[0])
            allowed[i] = [p for p in allowed[i] if p.split("/")[3] == disk]
    paths = [p for ps in allowed.values() for p in ps]
    if read_file is not None:
        contents = {p: (read_file(p) or "") for p in paths}
    else:
        contents = _parse(run("bash -c " + shlex.quote(_read_script(paths)))) if paths else {}

    docs_out = []
    for i, s in enumerate(specs):
        ps = [p for p in allowed.get(i, []) if contents.get(p, "").strip()]
        if not ps:
            continue
        if s["kind"] == "tree":
            lines = []
            for p in ps:
                val = " ".join(contents[p].split())
                key = s["prefix"] + p[len(s["glob"].split("*")[0].split("{")[0]):].replace("/", ".") if s["prefix"] else p
                lines.append(f"{key} = {val}")
            text = "\n".join(lines)
            if public:
                text = PUBLIC_DROP.sub("#dropped", text)
                text = "\n".join(l for l in text.splitlines() if not l.startswith("#dropped"))
            docs_out.append({"path": s["path"], "docs": s["docs"], "text": text})
            continue
        for p in ps:
            text = contents[p]
            xf = s["xf"] or {"passwd": "passwd", "group": "group"}.get(p.rsplit("/", 1)[-1])
            if xf in ("passwd", "group"):
                # public sample: only the distro's static ids (< 100), no site-specific accounts
                text = XF[xf](text, 100 if public else 1000)
            elif xf:
                text = XF[xf](text)
            if p.startswith("/etc/") and xf is None:
                text = (strip_comments(text) or text) if len(text.splitlines()) > 40 else text
            if s["lines"]:
                n = len(text.splitlines())
                text = "\n".join(text.splitlines()[:s["lines"]]) + (f"\n... ({n - s['lines']} more lines)" if n > s["lines"] else "")
            docs_out.append({"path": p, "docs": s["docs"], "text": text})
    if public:  # the sampled process's cgroup path names the host's own service layout
        for d in docs_out:
            if d["path"] == "/proc/self/cgroup":
                d["text"] = re.sub(r"^(\d+:[^:]*:).*$", r"\1/[cgroup path removed]", d["text"], flags=re.M)
    host = "".join(contents.get("/proc/sys/kernel/hostname", "").split())
    for d in docs_out:
        if public and len(host) > 2:
            d["text"] = re.sub(re.escape(host) + r"|\b" + re.escape(host.split(".")[0]) + r"\b", "[HOST]", d["text"])
        d["text"] = redact(d["text"])
    return docs_out


def to_chunks(docs, origin):
    """origin: 'sample' (public box snapshot) or 'prod'. Each chunk names its path and docs."""
    from rag.chunk import text_chunks
    out = []
    what = "sample snapshot from a Linux box" if origin == "sample" else "snapshot from this server"
    for d in docs:
        head = f"{d['path']} — {what} (redacted)."
        if d["docs"]:
            head += "\nDocs: " + "; ".join(d["docs"])
        for _, path, loc, body in text_chunks(d["text"], d["path"], 80):
            out.append((f"{d['path']} {what}", path, loc, head + "\n\n" + body))
    return out


def main():
    ap = argparse.ArgumentParser()
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--ssh")
    g.add_argument("--local", action="store_true")
    ap.add_argument("out")
    a = ap.parse_args()
    from rag.collect_prod import Runner
    docs = collect(Runner(None if a.local else a.ssh), public=True)
    kernel = next((d["text"] for d in docs if d["path"] == "/proc/version"), "")
    with open(a.out, "w") as f:
        json.dump({"source": "Linux " + " ".join(kernel.split()[2:3]), "files": docs}, f, indent=1)
    print(f"{len(docs)} files -> {a.out}", file=sys.stderr)


if __name__ == "__main__":
    main()
