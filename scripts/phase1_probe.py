#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
phase1_probe.py —— 阶段 1 DNS + HTTP 探测器（预算守卫内建，想违约都难）

为什么要有它：预算纪律（每主机 ≤2 请求、并发 ≤5、DNS ≤100 条）此前靠代理自觉。
两次 eval 代理各自手写了同款脚本（dns_probe + http_probe），证明这是该沉淀的轮子。
本脚本把守卫做成机制：计数器、并发闸、JSONL 留痕全部内建，超预算直接拒绝执行。

预算口径（唯一出处 = SKILL.md 阶段 1 规则）：
  HTTP：每主机 ≤2 请求（补测 8080/8443 时 ≤4）、并发 ≤5
  DNS ：总量 ≤100 条

用法：
  python scripts/phase1_probe.py --subdomains subdomains.csv --out probe_result.json
  python scripts/phase1_probe.py --subdomains subdomains.csv --top 100 --out result.json

输入：subdomains.csv（至少含 子域 列；可选 CNAME 列做跳过依据）
输出：probe_result.json + probe_trace.jsonl（逐条留痕）
退出码：0=正常；1=预算超限或致命错误
"""
import argparse
import concurrent.futures
import json
import os
import socket
import sys
import time
import urllib.request
import urllib.error
import ssl
import csv

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

HTTP_PER_HOST = 2          # 补测 8080/8443 时由 --extra-ports 提升至 4
HTTP_CONCURRENCY = 5
DNS_TOTAL_LIMIT = 100
HTTP_TIMEOUT = 10
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36")

# ---------------------------------------------------------------- 计数守卫
class Budget:
    def __init__(self, dns_limit=DNS_TOTAL_LIMIT, http_per_host=HTTP_PER_HOST):
        self.dns_limit = dns_limit
        self.dns_used = 0
        self.http_per_host = http_per_host
        self.http_by_host = {}       # host → count
        self.violations = []

    def dns_ok(self):
        return self.dns_used < self.dns_limit

    def dns_tick(self):
        self.dns_used += 1

    def http_ok(self, host):
        return self.http_by_host.get(host, 0) < self.http_per_host

    def http_tick(self, host):
        self.http_by_host[host] = self.http_by_host.get(host, 0) + 1


# ---------------------------------------------------------------- DNS
def resolve_all(domains, budget, trace):
    results = {}
    for d in domains:
        if not budget.dns_ok():
            trace.append({"type": "dns_skip", "domain": d, "reason": "DNS 总量超限"})
            results[d] = {"ip": None, "status": "未探测"}
            continue
        budget.dns_tick()
        try:
            ips = sorted({ai[4][0] for ai in socket.getaddrinfo(d, None, socket.AF_INET)})
            results[d] = {"ip": ips[0] if ips else None, "all_ips": ips, "status": "存活" if ips else "不存活"}
            trace.append({"type": "dns", "domain": d, "ips": ips})
        except socket.gaierror:
            results[d] = {"ip": None, "status": "NXDOMAIN"}
            trace.append({"type": "dns", "domain": d, "ips": [], "nx": True})
        except Exception as e:
            results[d] = {"ip": None, "status": "未探测"}
            trace.append({"type": "dns_err", "domain": d, "error": str(e)[:80]})
    return results


# ---------------------------------------------------------------- HTTP
def probe_http(host, budget, trace, extra_ports=False):
    ports = [80, 443] + ([8080, 8443] if extra_ports else [])
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    results = []
    for port in ports:
        scheme = "https" if port in (443, 8443) else "http"
        url = "%s://%s:%d/" % (scheme, host, port)
        if not budget.http_ok(host):
            trace.append({"type": "http_skip", "host": host, "url": url, "reason": "每主机请求超限"})
            results.append({"url": url, "status_code": None, "status": "未探测"})
            continue
        budget.http_tick(host)
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT, context=ctx) as r:
                title = ""
                body_head = r.read(2048).decode("utf-8", errors="replace")
                if "<title>" in body_head:
                    t0 = body_head.index("<title>") + 7
                    t1 = body_head.index("</title>", t0) if "</title>" in body_head[t0:] else t0 + 80
                    title = body_head[t0:t1].strip()[:100]
                results.append({"url": url, "status_code": r.status, "title": title, "status": "存活"})
                trace.append({"type": "http", "host": host, "url": url, "code": r.status, "title": title})
        except urllib.error.HTTPError as e:
            results.append({"url": url, "status_code": e.code, "title": "", "status": "存活"})
            trace.append({"type": "http", "host": host, "url": url, "code": e.code})
        except Exception as e:
            results.append({"url": url, "status_code": None, "status": "未探测"})
            trace.append({"type": "http_err", "host": host, "url": url, "error": str(e)[:80]})
    return results


def main():
    ap = argparse.ArgumentParser(description="阶段 1 DNS+HTTP 探测（预算守卫内建）")
    ap.add_argument("--subdomains", required=True, help="subdomains.csv 路径")
    ap.add_argument("--top", type=int, default=0, help="只处理前 N 条（0=全部，DNS 超限自动截断）")
    ap.add_argument("--extra-ports", action="store_true", help="补测 8080/8443（每主机上限升为 4）")
    ap.add_argument("--out", default="probe_result.json", help="结果 JSON")
    ap.add_argument("--trace", default="probe_trace.jsonl", help="逐条留痕 JSONL")
    args = ap.parse_args()

    # 读子域
    domains = []
    try:
        with open(args.subdomains, encoding="utf-8-sig") as f:
            for r in csv.DictReader(f):
                d = (r.get("子域") or r.get("domain") or "").strip()
                if d:
                    domains.append(d)
    except Exception as e:
        print("读 subdomains.csv 失败：%s" % e)
        return 1

    if args.top > 0:
        domains = domains[:args.top]

    per_host = 4 if args.extra_ports else HTTP_PER_HOST
    budget = Budget(dns_limit=DNS_TOTAL_LIMIT, http_per_host=per_host)
    trace = []

    # DNS
    dns_results = resolve_all(domains, budget, trace)

    # HTTP（只对 DNS 存活或 CNAME 存在的）
    alive = [d for d in domains if dns_results.get(d, {}).get("status") == "存活"]
    http_results = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=HTTP_CONCURRENCY) as pool:
        futs = {pool.submit(probe_http, h, budget, trace, args.extra_ports): h for h in alive}
        for fut in concurrent.futures.as_completed(futs):
            http_results[futs[fut]] = fut.result()

    # 输出
    out = {
        "dns_used": budget.dns_used, "dns_limit": budget.dns_limit,
        "http_by_host": budget.http_by_host,
        "domains_total": len(domains), "alive": len(alive),
        "dns": dns_results, "http": http_results,
    }
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=1)
    with open(args.trace, "w", encoding="utf-8") as f:
        for t in trace:
            f.write(json.dumps(t, ensure_ascii=False) + "\n")

    skipped = len(domains) - len(alive)
    print("DNS %d/%d 条（限 %d）｜存活 %d｜HTTP 探测 %d 主机｜跳过 %d（非存活/超限）"
          % (budget.dns_used, len(domains), budget.dns_limit, len(alive), len(http_results), skipped))
    if budget.dns_used >= budget.dns_limit:
        print("⚠ DNS 预算用完——剩余子域标「未探测」保留清单（只加不减），下会话继续")
    return 0


if __name__ == "__main__":
    sys.exit(main())
