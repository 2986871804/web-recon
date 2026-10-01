#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
mine_responses.py —— 从阶段 3 已落盘的响应体中挖掘新接口（递归发现通道）

什么是它：对 .body 文件执行五种模式提取，发现代码里没写死、由服务端下发的动态接口。
什么不是它：不发任何请求（纯本地 grep），不验证任何接口，不修改入口清单。

安全设计（三道闸）：
  ① 脚本本身零网络——只读 .body 文件，不存在"误跑危险接口"的网络行为
  ② 危险路径标记——输出中每个条目带「风险」列，匹配危险词的标「⚠高危」并单独汇总
  ③ 消费侧防线——高危条目的备注写明"验证前须人工确认"，agent 不应对高危条目
     自动发起验证（这是技能层纪律，脚本靠标记提醒）

用法：
  python scripts/mine_responses.py --dir <body文件目录> [--entry-list 入口清单.csv]
                                    [--site <站点>] [--csv out.csv] [--out report.txt] [--log log.txt]
  --entry-list 传入时与已有条目去重（占位符归一化），只输出新发现
退出码：0 = 正常；1 = 有致命错误
"""
import argparse
import collections
import csv
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from extract_endpoints import API_PREFIX, TEXT_EXTS  # noqa: E402

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# ---------------------------------------------------------------- 提取模式
# 五种模式按特异性排序，同一路径命中多模式时取首个（计数仍全记）
PATTERNS = [
    ("error_echo", re.compile(
        r'"path"\s*:\s*"(/[^"]{2,200})"')),
    ("hateoas", re.compile(
        r'"(?:next|prev|self|related|first|last|href|link)"\s*:\s*"(/[^"]{2,200})"')),
    ("url_field", re.compile(
        r'"[a-z_]*(?:url|uri|link|href|endpoint|callback)"\s*:\s*"(/[^"]{2,200})"')),
    ("path_value", re.compile(
        r'"(/(?:' + API_PREFIX + r')/[^"]{2,200})"')),
    ("nested_uri", re.compile(
        r'"(/[a-z]+/\d+/[a-z]+(?:/[^"]{0,100})?)"')),
]

# ---------------------------------------------------------------- 危险词
# 这些词出现在路径中时标记「⚠高危」——不是因为脚本会触发它们（脚本零请求），
# 而是因为后续如果有人/agent 对它们发 GET，可能触发服务端副作用（如 export 生成大文件、
# logout 使会话失效、callback 触发下游动作）。只标记不丢弃（只加不减）。
DANGER_WORDS = re.compile(
    r'/logout|/signout|/export|/download|/delete|/remove|/destroy|/reset|/flush|/clear'
    r'|/callback|/webhook|/notify|/admin|/upload|/import|/create|/update|/edit|/modify'
    r'|/write|/send|/pay|/order|/submit|/password|/token|/secret|/key|/credential', re.I)

ASSET_RE = re.compile(
    r'\.(js|css|png|jpe?g|gif|webp|svg|ico|woff2?|ttf|mp4|json|xml|pdf)(\?|$)', re.I)


def normalize_path(p):
    """归一化：数字段→{id}，去 query，补前导斜杠"""
    p = p.split("?")[0].split("#")[0]
    if not p.startswith("/"):
        p = "/" + p
    segs = []
    for s in p.strip("/").split("/"):
        if re.fullmatch(r"\d+", s):
            segs.append("{id}")
        elif re.fullmatch(r"[0-9a-f-]{8,}", s):
            segs.append("{uuid}")
        else:
            segs.append(s)
    return "/" + "/".join(segs)


def is_valid_path(p):
    """过滤明显不是接口的路径"""
    if not p or len(p) < 4 or len(p) > 300:
        return False
    if ASSET_RE.search(p):
        return False
    if p.startswith(("//", "javascript:", "data:", "#")):
        return False
    if " " in p:
        return False
    if not re.match(r"^/[a-zA-Z0-9_{\-]+(/[a-zA-Z0-9_{}\-]+){0,8}$", p):
        return False
    return True


def mine_file(path):
    """对一个 .body 文件执行五模式提取，返回 [(norm_path, raw_path, pattern, line_no)]"""
    try:
        text = open(path, encoding="utf-8", errors="replace").read()
    except OSError:
        return []
    out = []
    for pat_name, pat in PATTERNS:
        for m in pat.finditer(text):
            raw = m.group(1)
            if not is_valid_path(raw):
                continue
            norm = normalize_path(raw)
            line = text.count("\n", 0, m.start()) + 1
            out.append((norm, raw, pat_name, line))
    return out


def main():
    ap = argparse.ArgumentParser(
        description="响应体挖掘：从已落盘的 .body 文件中发现新接口（零请求，离线）")
    ap.add_argument("--dir", required=True, help="阶段 3 落盘的 .body 文件目录")
    ap.add_argument("--entry-list", help="已有入口清单 CSV——传入时与已有条目去重")
    ap.add_argument("--site", default="-", help="站点归属")
    ap.add_argument("--csv", help="新发现 CSV（UTF-8 BOM）")
    ap.add_argument("--out", help="报告文件（UTF-8）")
    ap.add_argument("--log", help="控制台输出改写入该文件（UTF-8）")
    args = ap.parse_args()

    # 已有条目（去重用）
    existing = set()
    if args.entry_list and os.path.isfile(args.entry_list):
        try:
            for r in csv.DictReader(open(args.entry_list, encoding="utf-8-sig")):
                existing.add(normalize_path(r.get("URL", r.get("接口路径", ""))))
        except Exception:
            pass

    # 挖掘
    all_finds = {}          # norm_path → {raw, pattern, files, danger}
    body_files = 0
    for root, _, fs in os.walk(args.dir):
        for f in sorted(fs):
            if not f.endswith(".body"):
                continue
            body_files += 1
            fp = os.path.join(root, f)
            for norm, raw, pat, line in mine_file(fp):
                if norm in existing:
                    continue
                if norm not in all_finds:
                    all_finds[norm] = {
                        "raw": raw, "pattern": pat, "files": set(),
                        "danger": bool(DANGER_WORDS.search(norm))
                    }
                all_finds[norm]["files"].add(f)

    # 分类
    danger_items = {k: v for k, v in all_finds.items() if v["danger"]}
    safe_items = {k: v for k, v in all_finds.items() if not v["danger"]}
    pat_counts = collections.Counter(v["pattern"] for v in all_finds.values())

    # 输出
    L = []
    L.append("=== 响应体挖掘 ===")
    L.append("扫描 %d 个 .body 文件｜新发现 %d 条（去重后）｜其中 ⚠高危 %d 条｜已有 %d 条不重复计入"
             % (body_files, len(all_finds), len(danger_items), len(existing)))
    L.append("模式命中：%s" % " · ".join("%s %d" % kv for kv in pat_counts.most_common()))
    L.append("")

    if danger_items:
        L.append("⚠⚠ 高危条目（路径含危险词，验证前须人工确认——GET 也可能触发副作用）：")
        for k, v in sorted(danger_items.items()):
            L.append("  ⚠ %s  (%s, 来自 %s)" % (k, v["pattern"], ",".join(sorted(v["files"])[:3])))
        L.append("")

    L.append("⚠ 全部条目状态=待批准：响应体挖掘产物不自动进入验证，须用户点名后方可验证。")
    L.append("")

    if safe_items:
        L.append("常规条目（无危险词，用户批准后可验证）：")
        for k, v in sorted(safe_items.items()):
            L.append("  %s  (%s, 来自 %s)" % (k, v["pattern"], ",".join(sorted(v["files"])[:3])))
    else:
        L.append("（无新发现——响应体中的路径全部已在入口清单中）")

    L.append("")
    L.append("⚠ 本脚本零网络请求，只发现不验证。全部产出状态=待批准——")
    L.append("  agent 须将此清单呈报用户，用户点名后方可进入阶段 3 验证。")
    L.append("  高危标记（export/delete/callback 等）是额外参考信息，不替用户做决定。")

    out_text = "\n".join(L)

    if args.csv:
        with open(args.csv, "w", encoding="utf-8-sig", newline="") as f:
            w = csv.DictWriter(f, fieldnames=[
                "接口路径", "原始值", "模式", "来源文件", "状态", "风险", "站点"])
            w.writeheader()
            for k, v in sorted(all_finds.items()):
                w.writerow({
                    "接口路径": k, "原始值": v["raw"], "模式": v["pattern"],
                    "来源文件": ",".join(sorted(v["files"])),
                    "状态": "待批准",       # 响应体挖掘产物一律待用户批准，不自动验证
                    "风险": "⚠高危" if v["danger"] else "", "站点": args.site})

    if args.out:
        open(args.out, "w", encoding="utf-8").write(out_text + "\n")
    if args.log:
        open(args.log, "w", encoding="utf-8").write(out_text + "\n")
    else:
        print(out_text)

    return 0


if __name__ == "__main__":
    sys.exit(main())
