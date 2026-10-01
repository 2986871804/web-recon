#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""前端 JS API 端点提取器 v3（六轮实战迭代版）

用法: python extract_apis.py [目录] [--out 报告文件] [--log 日志文件]
      默认扫当前目录；扫描面与 extract_endpoints 一致（js/json/html/css/ts/vue/map 等，
      由 extract_endpoints.TEXT_EXTS 统一定义）

迭代史（坑即设计约束）:
  v1: 关键词白名单过滤      → 漏掉不在词表里的路径（search-v2）
  v2: 补协议相对 URL        → 捞回 //upload.host/api 类
  v3: 去关键词化改分类式 + 补无前导斜杠相对路径 + 上下文分类修 off-by-one

设计要点:
  - 全量提取 + 分级分类（grade A/B/C），不做白名单过滤
  - 三种形态都匹配: /path、//host/path、"api/cf/..."（无前导斜杠）
  - call_site 判定看路径字符串收尾引号之后的内容（跳过引号，否则永远失配）
"""
import argparse
import os
import re
import sys
from collections import defaultdict

from extract_endpoints import (TEXT_EXTS, API_PREFIX, load_fetch_exclusions,
                               FETCH_REPORT, find_fetch_reports, hdr_bad)  # 扫描面/前缀/判定联动同源

ASSET_RE = re.compile(r'\.(js|css|png|jpe?g|gif|webp|svg|ico|woff2?|ttf|mp4|json|html?|map|vue)(\?|$)', re.I)
STR_RE = re.compile(r'(["\'])(/[^"\']{2,200})\1')
REL_RE = re.compile(r'(["\'])((?:' + API_PREFIX + r')/[a-zA-Z0-9_\-/]{3,150})\1')
PROT_REL_RE = re.compile(r'(["\'])(//[a-z0-9.\-]+\.[a-z]{2,}(/[^\s"\']*)?)\1', re.I)
URL_RE = re.compile(r'(["\'])(https?://[a-zA-Z0-9\-.]+(?:/[^\s"\']{0,150})?)\1')


def classify(text, pos, path):
    """上下文分类：call_site=真调用点 / sdk_const=SDK常量 / bare=待核"""
    before, after = text[max(0, pos - 120):pos], text[pos + len(path) + 1:pos + len(path) + 41]
    if re.match(r'\s*,\s*(body|e|t|n|r|o|\{|")', after) or re.match(r'\s*,\s*$', after):
        return 'call_site'
    if re.search(r'(Error\w*|code|err)\s*[=.:]\s*$', before, re.I) or re.search(r'_(net|result|error)$', path):
        return 'sdk_const'
    if 'jsonp' in before or 'sendBeacon' in before or 'XMLHttp' in before or 'fetch' in before:
        return 'call_site'
    return 'bare'


def grade(path):
    p = path.lower()
    if re.match(r'^/(api|web|cgi|gateway|gw|rpc|srv|service)/', p):
        return 'A'
    if any(seg in p for seg in ('/get', '/list', '/query', '/search', '/report', '/login',
                                '/user', '/upload', '/pay', '/order', '/verify', '/send',
                                '/detail', '/info', '/submit', '/create', '/delete',
                                '/update')) \
            or re.search(r'/v\d+', p):   # 版本路径用正则——'/v[0-9]' 当字面量 in 永远 False（实测降级事故）
        return 'B'
    return 'C'


def render(base, reconcile_fine=None):
    buckets, hosts = defaultdict(set), set()
    excl, report_errors = load_fetch_exclusions(find_fetch_reports(base))
    dl_excluded = skipped_ext = 0
    for root, _, fs in os.walk(base):                    # 与 extract_endpoints/scan_comments 一致：递归
        for f in sorted(fs):
            path = os.path.join(root, f)
            if f == FETCH_REPORT:
                dl_excluded += 1
                continue
            if (os.path.abspath(root), f) in excl or (report_errors and hdr_bad(path)):
                dl_excluded += 1                       # 非 OK 判定（或侧车回退）：不得用于提取
                continue
            if not f.lower().endswith(TEXT_EXTS):
                skipped_ext += 1
                continue
            if not os.path.isfile(path):
                continue
            try:
                text = open(path, encoding='utf-8', errors='ignore').read()
            except OSError:
                continue
            # STR 原样（自带前导 /）；REL 传 raw（无斜杠）给 classify——先补斜杠再传会把
            # pos+len(path)+1 的收尾引号跳位多错 1 字符（v3 只修了 STR 那半的 off-by-one）
            matches = [(m.start(2), m.group(2), False) for m in STR_RE.finditer(text)]
            matches += [(m.start(2), m.group(2), True) for m in REL_RE.finditer(text)]
            for pos, raw, rel in matches:
                s = ('/' + raw) if rel else raw
                if ASSET_RE.search(s) or s.startswith('//'):
                    continue
                if not re.match(r'^/[a-zA-Z0-9_\-]+(/[a-zA-Z0-9_\-{}.]+){0,6}$', s):
                    continue
                buckets[(grade(s), classify(text, pos, raw))].add((s, f))
            for m in PROT_REL_RE.finditer(text):
                u = m.group(2).split('?')[0]
                if not ASSET_RE.search(u):
                    buckets[('P', 'proto_rel')].add((u, f))
            for m in URL_RE.finditer(text):
                u = m.group(2).split('?')[0]
                if re.match(r'^https?://[a-z0-9.-]+\.[a-z]{2,}/?$', u, re.I):
                    hosts.add((u, f))

    L = []
    if report_errors:
        L.append("⚠ 判定报告读取失败 %d 份——排除机制未生效，非 OK 文件已全部进入粗筛" % len(report_errors))
    if dl_excluded:
        L.append("（因下载判定排除 %d 个文件——非 OK 不得用于提取）" % dl_excluded)
    if skipped_ext:
        L.append("（跳过非文本 %d 个——与精提同口径，无静默丢弃）" % skipped_ext)
    for (g, cls) in sorted(buckets.keys(), reverse=True):
        items = sorted(buckets[(g, cls)])
        L.append(f'### grade{g}::{cls} ({len(items)})')
        for s, f in items:
            L.append(f'  {s}    <{f[:12]}>')
        L.append('')
    L.append(f'### hosts ({len(hosts)})')
    for u, f in sorted(hosts):
        L.append(f'  {u}    <{f[:12]}>')
    L.append('')

    # 粗筛/精提对账（--reconcile-fine）：粗筛抓到而精提漏掉的路径 = 精提通道盲区候选。
    # 此前这道对账由人工承担（三道闸的第三闸）——裸 fetch 盲区就是粗筛兜住、精提漏掉、
    # 无人 diff 才静默存活到 eval 才暴露的。占位符模板按段匹配：{x} 段 ≙ 任意非 / 字面段。
    if reconcile_fine:
        import csv as _csv
        coarse = {s for (g, cls) in buckets for (s, _f) in buckets[(g, cls)]
                  if g in ("A", "B")}
        try:
            fine_paths = [r["接口路径"] for r in
                          _csv.DictReader(open(reconcile_fine, encoding="utf-8-sig"))]
        except Exception as e:
            L.append("⚠ 对账失败：精提 CSV 读取不了（%s）——盲区对账未执行" % e)
            fine_paths = None
        if fine_paths is not None:
            import re as _re
            pats = []
            for fp in fine_paths:
                segs = [_re.escape(seg) if not (seg.startswith("{") and seg.endswith("}"))
                        else "[^/]+" for seg in fp.strip("/").split("/")]
                pats.append(_re.compile("^/" + "/".join(segs) + "$"))
            uncovered = sorted(s for s in coarse
                               if not any(p.match(s) for p in pats))
            L.append("⚠ 粗筛有/精提无 %d 条（精提通道盲区候选，人工复核前不得丢弃）：%s%s"
                     % (len(uncovered), ", ".join(uncovered[:10]),
                        "…" if len(uncovered) > 10 else ""))
    return "\n".join(L), bool(report_errors)


def main():
    ap = argparse.ArgumentParser(description="JS 静态粗筛：路径分级 + 调用点分类")
    ap.add_argument("dir", nargs="?", default=".", help="JS/HTML 目录（默认当前目录）")
    ap.add_argument("--reconcile-fine", dest="reconcile_fine",
                    help="精提 CSV 路径——对账：粗筛抓到而精提漏掉的路径（盲区候选）")
    ap.add_argument("--out", help="结果报告写入该文件（UTF-8），控制台照常打印")
    ap.add_argument("--log", help="控制台输出改写入该文件（UTF-8），不再打印")
    args = ap.parse_args()

    text, degraded = render(args.dir, reconcile_fine=args.reconcile_fine)
    if args.out:
        open(args.out, "w", encoding="utf-8").write(text + "\n")
    if args.log:
        open(args.log, "w", encoding="utf-8").write(text + "\n")
    else:
        print(text)
    return 1 if degraded else 0                    # 0=正常，1=判定报告损坏（结果未经过滤）


if __name__ == '__main__':
    sys.exit(main())
