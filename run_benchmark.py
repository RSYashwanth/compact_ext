#!/usr/bin/env python3
import argparse
import os
import re
import signal
import subprocess
import sys
import threading
import time

ROOT = os.path.dirname(os.path.abspath(__file__))
POLICIES = os.path.join(ROOT, "policies")
WORKLOADS = os.path.join(ROOT, "workloads")
LOADER = os.path.join(POLICIES, "compact_ext_run.out")
STEPS = ("setup", "prepare", "run", "cleanup")
PAGE_MB = os.sysconf("SC_PAGE_SIZE") / 2**20
HZ = os.sysconf("SC_CLK_TCK")

VMSTAT = [
    "thp_fault_alloc", "thp_fault_fallback",
    "compact_stall", "compact_success", "compact_fail",
    "compact_migrate_scanned", "compact_free_scanned",
    "compact_daemon_wake", "compact_daemon_migrate_scanned",
    "compact_daemon_free_scanned", "compact_evicted",
    "pgmigrate_success", "pgmigrate_fail",
    "pgsteal_kswapd", "pgsteal_direct", "pgscan_kswapd", "pgscan_direct",
    "pgpgin", "pgmajfault", "workingset_refault_file",
]
WARNING = re.compile(r"BUG:|WARNING:|Oops|Call Trace")


def read(path):
    with open(path) as f:
        return f.read()


def write(path, text):
    with open(path, "w") as f:
        f.write(text)


def vmstat():
    out = {}
    for line in read("/proc/vmstat").splitlines():
        k, v = line.split()
        out[k] = int(v)
    return out


def node_meminfo(node):
    out = {}
    for line in read(f"/sys/devices/system/node/node{node}/meminfo").splitlines():
        f = line.split()
        out[f[2].rstrip(":")] = int(f[3])
    return out


def free_2m_blocks(node):
    total = 0
    for line in read("/proc/buddyinfo").splitlines():
        f = line.split()
        if f[1] == f"{node},":
            counts = list(map(int, f[4:]))
            total += sum(c << (o - 9) for o, c in enumerate(counts) if o >= 9)
    return total


def kthread_cpu_s(name):
    for pid in os.listdir("/proc"):
        if pid.isdigit():
            try:
                if read(f"/proc/{pid}/comm").strip() == name:
                    f = read(f"/proc/{pid}/stat").rsplit(")", 1)[1].split()
                    return (int(f[11]) + int(f[12])) / HZ
            except OSError:
                pass
    return 0.0


def kernel_warnings():
    out = subprocess.run(["dmesg"], capture_output=True, text=True).stdout
    return sum(1 for line in out.splitlines() if WARNING.search(line))


def snapshot(node):
    return {
        "vmstat": vmstat(),
        "mem": node_meminfo(node),
        "free_2m": free_2m_blocks(node),
        "kcompactd_s": kthread_cpu_s(f"kcompactd{node}"),
    }


class Policy:

    def __init__(self, name, settings, node):
        obj = os.path.join(POLICIES, f"compact_ext_{name}.bpf.o")
        for path in (LOADER, obj):
            if not os.path.exists(path):
                sys.exit(f"{path} is missing; build the policies (build_policies.sh)")
        cmd = [LOADER, "-n", str(node)]
        for s in settings:
            cmd += ["-s", s]
        self.proc = subprocess.Popen(cmd + [obj], stdout=subprocess.PIPE,
                                     stderr=subprocess.STDOUT, text=True)
        self.lines = []
        attached = threading.Event()

        def drain():
            for line in self.proc.stdout:
                self.lines.append(line.rstrip("\n"))
                if "attached to node" in line:
                    attached.set()
            attached.set()

        self.reader = threading.Thread(target=drain, daemon=True)
        self.reader.start()
        attached.wait(30)
        if self.proc.poll() is not None or not any("attached to node" in l
                                                   for l in self.lines):
            self.proc.kill()
            sys.exit("could not attach the policy:\n" + "\n".join(self.lines))

    def detach(self):
        self.proc.send_signal(signal.SIGINT)
        self.proc.wait(60)
        self.reader.join(5)
        out, section = {"settings": {}, "counters": {}}, None
        for line in self.lines:
            if line.startswith("settings:"):
                section = "settings"
            elif line.startswith("counters"):
                section = "counters"
            elif section and line.startswith("  ") and " = " in line:
                k, v = line.strip().split(" = ", 1)
                out[section][k] = v
            else:
                section = None
        return out


class StepFailed(Exception):
    pass


def step(workload_dir, name, env):
    t0 = time.monotonic()
    ret = subprocess.run([os.path.join(workload_dir, name)], env=env,
                         stdout=sys.stderr).returncode
    if ret:
        raise StepFailed(f"{name} failed (exit status {ret})")
    return time.monotonic() - t0


def main():
    ap = argparse.ArgumentParser(
        description="Benchmark a compact_ext policy on a workload and write the "
                    "results as key: value lines.",
        epilog="A workload is a directory under workloads/ with four executables, "
               "setup, prepare, run and cleanup, run as root with NODE, DATA_DIR "
               "and (for run) METRICS set. Kernel counters cover run only.")
    ap.add_argument("workload", help="a directory under workloads/")
    ap.add_argument("--policy", default="none",
                    help="a policy in policies/ (compact_ext_NAME.bpf.o), or none")
    ap.add_argument("-s", "--set", action="append", default=[], metavar="NAME=VALUE",
                    help="a setting of the policy")
    ap.add_argument("--node", type=int, default=0, help="the NUMA node under test")
    ap.add_argument("--out", help="results file (default "
                    "results/WORKLOAD-POLICY-TIME.txt)")
    ap.add_argument("--data-dir",
                    help="the workload's files (default /var/tmp/compact_ext/WORKLOAD)")
    ap.add_argument("--no-clean", action="store_true",
                    help="keep the page cache and memory layout from before")
    args = ap.parse_args()

    if os.geteuid() != 0:
        sys.exit("run_benchmark.py must run as root")
    wdir = os.path.join(WORKLOADS, args.workload)
    for s in STEPS:
        if not os.access(os.path.join(wdir, s), os.X_OK):
            sys.exit(f"{wdir}/{s} is missing or not executable")
    if not os.path.isdir(f"/sys/devices/system/node/node{args.node}"):
        sys.exit(f"there is no NUMA node {args.node}")
    if args.set and args.policy == "none":
        sys.exit("-s needs a policy")

    stamp = time.strftime("%Y%m%d-%H%M%S")
    out = args.out or os.path.join("results", f"{args.workload}-{args.policy}-{stamp}.txt")
    os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
    data_dir = args.data_dir or f"/var/tmp/compact_ext/{args.workload}"
    metrics = os.path.abspath(out) + ".workload"
    env = dict(os.environ, NODE=str(args.node), DATA_DIR=data_dir)

    res = {
        "workload": args.workload,
        "policy": args.policy,
        "node": args.node,
        "kernel": os.uname().release,
        "date": time.strftime("%Y-%m-%d %H:%M:%S"),
        "thp.enabled": re.search(r"\[(\w+)\]", read(
            "/sys/kernel/mm/transparent_hugepage/enabled")).group(1),
        "thp.defrag": re.search(r"\[([\w+]+)\]", read(
            "/sys/kernel/mm/transparent_hugepage/defrag")).group(1),
        "sysctl.compaction_proactiveness":
            read("/proc/sys/vm/compaction_proactiveness").strip(),
    }
    warnings = kernel_warnings()
    try:
        res["time.setup_s"] = round(step(wdir, "setup", env), 1)
    except StepFailed as e:
        sys.exit(str(e))

    if not args.no_clean:
        os.sync()
        write("/proc/sys/vm/drop_caches", "3")
        write(f"/sys/devices/system/node/node{args.node}/compact", "1")
        time.sleep(1)

    policy = Policy(args.policy, args.set, args.node) if args.policy != "none" else None
    failed = None
    try:
        if os.path.exists(metrics):
            os.unlink(metrics)
        res["time.prepare_s"] = round(step(wdir, "prepare", env), 1)
        a = snapshot(args.node)
        res["time.run_s"] = round(step(wdir, "run", dict(env, METRICS=metrics)), 1)
        b = snapshot(args.node)
    except StepFailed as e:
        failed = str(e)
    finally:
        try:
            step(wdir, "cleanup", env)
        except StepFailed as e:
            failed = failed or str(e)
        detached = policy.detach() if policy else None
    if failed:
        sys.exit(failed)

    if os.path.exists(metrics):
        for line in read(metrics).splitlines():
            k, sep, v = line.partition(":")
            if sep:
                res[k.strip()] = v.strip()
        os.unlink(metrics)

    dv = {k: b["vmstat"].get(k, 0) - a["vmstat"].get(k, 0) for k in VMSTAT}
    allocstall = sum(v - a["vmstat"].get(k, 0) for k, v in b["vmstat"].items()
                     if k.startswith("allocstall_"))
    res.update({
        "mem.free_2m_blocks_before": a["free_2m"],
        "mem.free_2m_blocks_after": b["free_2m"],
        "mem.page_cache_mb_before": a["mem"]["FilePages"] >> 10,
        "mem.page_cache_mb_after": b["mem"]["FilePages"] >> 10,
        "mem.free_mb_before": a["mem"]["MemFree"] >> 10,
        "mem.free_mb_after": b["mem"]["MemFree"] >> 10,
        "mem.slab_mb_before": a["mem"]["Slab"] >> 10,
        "mem.page_cache_dropped_mb": round((dv["pgsteal_kswapd"] + dv["pgsteal_direct"] +
                                            dv["compact_evicted"]) * PAGE_MB),
        "mem.page_cache_dropped_by_compaction_mb": round(dv["compact_evicted"] * PAGE_MB),
        "compaction.kcompactd_cpu_s": round(b["kcompactd_s"] - a["kcompactd_s"], 2),
        "reclaim.direct_stalls": allocstall,
    })
    res.update((f"vmstat.{k}", v) for k, v in dv.items())
    if detached:
        res.update((f"policy.setting.{k}", v) for k, v in detached["settings"].items())
        res.update((f"policy.{k}", v) for k, v in detached["counters"].items())
    res["kernel.warnings"] = kernel_warnings() - warnings

    text = "".join(f"{k}: {v}\n" for k, v in res.items())
    write(out, text)
    print(text, end="")
    print(f"wrote {out}", file=sys.stderr)


if __name__ == "__main__":
    main()
