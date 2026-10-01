#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
scan_comments.py —— 注释敏感线索扫描（独立产物通道，离线）

为什么独立：正则形状的密钥（AKIA/eyJ 等）在全文 grep 里能撞上，但注释里的
中文凭据（"测试账号 admin / 密码：Admin@123"）、内网裸地址、注释掉的旧接口
没有形状可撞，只能按"注释 + 触发词"找。产出是**线索**不是已确认泄露——
核验前不得并入泄露点清单。

三类目标：
  1. 中文/英文凭据   触发词（密码|口令|账号|用户名|凭据|密钥|secret|token|...）+ 紧随的值
  2. 内网裸地址      RFC1918 段（可选 :端口）+ .internal/.corp/.lan/.local 主机名
  3. 注释掉的旧接口  /api|web|gateway|... 前缀路径（= 废弃线索，与提取器正常产出语义不同）

License 抑制：@license / Copyright / Licensed under 等横幅块整块滤除；
内容相同的注释块（每文件重复的 license 头）合并计数，不刷屏。

用法：
  python scan_comments.py --dir <文本目录> [--csv out.csv] [--out report.txt] [--log log.txt]
  # 扫描面与 extract_endpoints.TEXT_EXTS 一致（JSON/map 类无注释语法，跳过并计数）
"""
import argparse
import collections
import csv
import os
import re
import sys

from extract_endpoints import (TEXT_EXTS, API_PREFIX, load_fetch_exclusions,
                               FETCH_REPORT, find_fetch_reports, hdr_bad)

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# ---------------------------------------------------------------- 注释切分
JS_LINE   = re.compile(r'(?<![:"\'/])//[^\n]*')          # 避开 http://
JS_BLOCK  = re.compile(r'/\*[\s\S]*?\*/')
HTML_CMT  = re.compile(r'<!--[\s\S]*?-->')

LICENSE_HINT = ("@license", "copyright (c)", "copyright ©", "©",
                "apache license", "gnu general", "mit license", "bsd license",
                "licensed under", "all rights reserved")

# ---------------------------------------------------------------- 三类目标
TRIG_CRED = re.compile(
    r'(密码|口令|账号|账户|用户名|凭据|密钥|鉴权码|'
    r'(?i:\b(?:secret|token|passwd|password|apikey|api_key|appkey)\b))'
    r'\s*[:：=是]{0,2}\s*["\']?([A-Za-z0-9_\-@.!#$%^&*+=]{4,48})')
INTRANET  = re.compile(
    r'(?<![\d.])((?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    r'|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}'
    r'|192\.168\.\d{1,3}\.\d{1,3})(?![\d.])(?::\d{1,5})?'      # (?![\d.]) 拦五段串（10.1.2.3.4）部分匹配
    r'|[a-z0-9\-]+\.(?:internal|corp|lan|local|intranet)\b)', re.I)
OLD_API   = re.compile(r'(?<![\w/])/' + API_PREFIX + r'/[A-Za-z0-9_\-/]{2,120}')


def comments_of(path, text):
    """按文件类型切注释块，返回 [(起始偏移, 块文本)]。
    含内容嗅探：.js 形态的 HTML 错误页（重定向落盘等）按 HTML 注释扫，与精提同口径。"""
    low = path.lower()
    if low.endswith((".json", ".map")):
        return []                                   # JSON 家族无注释语法
    head = text[:256].lstrip().lower()
    if low.endswith((".html", ".htm")) or head.startswith(("<!doctype html", "<html", "<head")):
        out = [(m.start(), m.group(0)) for m in HTML_CMT.finditer(text)]
    elif low.endswith(".vue"):
        # Vue SFC：模板区 HTML 注释 + 脚本区 JS 注释。JS 正则只作用于 <script> 区间——
        # 模板属性里的 //（协议相对 URL）会被 JS_LINE 当行注释切出假线索块（实测误报）
        out = [(m.start(), m.group(0)) for m in HTML_CMT.finditer(text)]
        for sm in re.finditer(r"<script[^>]*>([\s\S]*?)</script>", text):
            seg, base = sm.group(1), sm.start(1)
            out += [(base + m.start(), m.group(0)) for m in JS_BLOCK.finditer(seg)]
            out += [(base + m.start(), m.group(0)) for m in JS_LINE.finditer(seg)]
    else:                                           # js/ts/css 家族
        out = [(m.start(), m.group(0)) for m in JS_BLOCK.finditer(text)]
        out += [(m.start(), m.group(0)) for m in JS_LINE.finditer(text)]
    return out


# 内网 IP 的第二道判据：伴随线索词/端口/URL → 高置信；版本号/UA/时间戳语境 → 低置信
IP_CTX_UP   = re.compile(r'内网|网关|后台|直连|数据库|服务器|主机|地址|连接|'
                         r'(?i:backend|gateway|host|server|db|url|http)', )
IP_CTX_DOWN = re.compile(r'版本|(?i:version|user.?agent|\bua\b|timestamp)')


def ip_confidence(val, blk):
    if IP_CTX_DOWN.search(blk):
        return "低"
    if ":" in val or "http" in blk.lower() or IP_CTX_UP.search(blk):
        return "高"
    return "低"


def scan_file(path, hits, stats, seen_blocks):
    try:
        text = open(path, encoding="utf-8", errors="ignore").read()
    except OSError:
        return
    lineno_cache = {}
    for off, blk in comments_of(path, text):
        norm = re.sub(r"\s+", " ", blk).strip().lower()
        if any(h in norm for h in LICENSE_HINT):
            stats["license块滤除"] += 1
            continue
        if norm in seen_blocks:                     # 每文件重复的横幅 → 合并计数
            seen_blocks[norm] += 1
            continue
        seen_blocks[norm] = 1

        def fmt_ctx(s):
            # 证据本体格式：行内空白压单空格，换行显式标记 ⏎ —— 上下文只来自所属注释块，
            # 不跨块、不把多行伪装成一行（license 尾部等无关文本不得倒灌进证据）
            s = s.replace("\r", "")
            s = re.sub(r"[ \t]+", " ", s)
            s = re.sub(r"\n+", " ⏎ ", s)
            return s.strip(" \n⏎")

        def ctx_blk(local_pos):
            seg = blk[max(0, local_pos - 40): local_pos + 60]      # 夹在块内，不越界
            return fmt_ctx(seg)

        def line_of(pos):
            if pos not in lineno_cache:
                lineno_cache[pos] = text.count("\n", 0, pos) + 1
            return lineno_cache[pos]

        def add(kind, val, pos, ctxstr, conf="-"):
            key = (kind, val)
            if key not in hits:
                hits[key] = {"n": 0, "conf": conf, "ctx": ctxstr,
                             "src": "%s:%d" % (os.path.basename(path), line_of(pos))}
            hits[key]["n"] += 1
            # 同值多语境出现时置信只升不降：一处高置信语境即值得核验（证据聚合不丢最高档）
            if conf == "高":
                hits[key]["conf"] = "高"

        for m in TRIG_CRED.finditer(blk):
            add("中文/英文凭据", "%s=%s" % (m.group(1), m.group(2)),
                off + m.start(), ctx_blk(m.start()))
        for m in INTRANET.finditer(blk):
            add("内网裸地址", m.group(1), off + m.start(),
                ctx_blk(m.start()), ip_confidence(m.group(1), blk))
        for m in OLD_API.finditer(blk):
            add("注释旧接口", m.group(0), off + m.start(), ctx_blk(m.start()))


def main():
    ap = argparse.ArgumentParser(description="注释敏感线索扫描（独立通道）")
    ap.add_argument("--dir", required=True, help="文本目录（递归，扫描面同 extract_endpoints）")
    ap.add_argument("--site", default="-",
                    help="站点归属（subdomains.csv 的存活子域名；无归属场景显式记 '-'，规则见 delivery §1.5 站点列定义）")
    ap.add_argument("--csv", help="线索 CSV（UTF-8 BOM）")
    ap.add_argument("--out", help="结果报告写入该文件（UTF-8），控制台照常打印")
    ap.add_argument("--log", help="控制台输出改写入该文件（UTF-8），不再打印")
    args = ap.parse_args()

    hits, stats, seen_blocks = {}, collections.Counter(), {}
    files = skipped_json = dl_excluded = 0
    excl, report_errors = load_fetch_exclusions(find_fetch_reports(args.dir))
    for root, _, fs in os.walk(args.dir):
        for f in sorted(fs):
            if not f.lower().endswith(TEXT_EXTS):
                continue
            p = os.path.join(root, f)            # 先赋值——下方 hdr_bad(p) 降级路径依赖它（曾因顺序在损坏报告场景崩）
            if f == FETCH_REPORT or (os.path.abspath(root), f) in excl \
                    or (report_errors and hdr_bad(p)):
                dl_excluded += 1
                continue
            if p.lower().endswith((".json", ".map")):
                skipped_json += 1
            files += 1
            scan_file(p, hits, stats, seen_blocks)

    rows = [{"类别": k[0], "内容": k[1], "置信": v["conf"], "上下文": v["ctx"],
             "来源": v["src"], "重复次数": v["n"], "站点": args.site}
            for k, v in sorted(hits.items(), key=lambda kv: (kv[0][0], -kv[1]["n"]))]

    L = []
    L.append("=== 注释线索扫描 ===")
    if args.site == "-":
        L.append("⚠ 未传 --site：站点列全部为 '-'（多站点场景须可回答归属，规则见 delivery §1.5）")
    if report_errors:
        L.append("⚠ 判定报告读取失败 %d 份——排除机制未生效，非 OK 文件已全部进入扫描" % len(report_errors))
    L.append("扫描 %d 个文件（JSON/map 类无注释语法跳过 %d 个；因下载判定排除 %d 个）｜"
             "license 块滤除 %d 个｜"
             "重复注释块合并 %d 组｜线索 %d 条" %
             (files, skipped_json, dl_excluded, stats["license块滤除"],
              sum(1 for n in seen_blocks.values() if n > 1), len(rows)))
    by = collections.Counter(r["类别"] for r in rows)
    L.append("分类：" + ("、".join("%s %d 条" % kv for kv in by.items()) if by else "0 命中"))
    L.append("")
    L.append("⚠ 线索 ≠ 已确认泄露：核验（上下文+实际请求）后才可并入泄露点清单。")
    L.append("")
    for r in rows:
        tag = r["类别"] if r["置信"] == "-" else "%s|%s置信" % (r["类别"], r["置信"])
        L.append("  [%s] %s  (%s, ×%d)" % (tag, r["内容"], r["来源"], r["重复次数"]))
        L.append("      …%s…" % r["上下文"])

    out_text = "\n".join(L)
    if args.csv:
        with open(args.csv, "w", encoding="utf-8-sig", newline="") as f:
            w = csv.DictWriter(f, fieldnames=["类别", "内容", "置信", "上下文", "来源", "重复次数", "站点"])
            w.writeheader()
            w.writerows(rows)
    if args.out:
        open(args.out, "w", encoding="utf-8").write(out_text + "\n")
    if args.log:
        open(args.log, "w", encoding="utf-8").write(out_text + "\n")
    else:
        print(out_text)
    return 1 if report_errors else 0              # 0=正常，1=判定报告损坏（结果未经过滤）


if __name__ == "__main__":
    sys.exit(main())
