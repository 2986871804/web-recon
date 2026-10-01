#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
run_regression.py —— 本技能自带脚本的回归测试（离线，零目标请求）

为什么要有它：本技能的脚本靠"判定联动"保证一条安全规则（非 OK 文件不得用于提取），
而这类机制最容易在改动中**静默失效**——看起来在工作，其实没生效。
本脚本把以下行为钉成可复跑的断言，改动前后各跑一次即可发现退化：

断言设计纪律：每个检查组必须含**正向项**（期望内容在场）——否定断言只证明"没做错"，
证明不了"做成了"。两轮真实事故都由纯否定断言放行：scan_comments 降级路径崩溃恰好
exit 1（与降级同签名）；extract_apis 循环缩进退化只扫每目录末文件（排除断言仍绿）。

  A. hdr_verdict()：侧车判定重建（状态码 / 截断 / 无 CL / 旧侧车 / BOM）
  B. 判定联动：报告（正常 / 带 BOM / 损坏 / 子目录 / 缺失 / 自身内容）→ 三个脚本的
     排除行为与三态（无报告=静默正常；损坏=告警+退出码 1）
  C. 提取核心规则不回归：占位符、复数方法键、补斜杠、参数名、{API_HOST} 常量回填、
     WS/SSE/wss/GraphQL 四通道、0 命中可见性
  D. 注释扫描：命中 / 噪声挡住 / 置信分级与只升不降 / 证据本体（⏎、不跨块）
  E. safe_fetch 生产者契约：本地回环 HTTP 服务真实下载——侧车首行 Status、报告判定
     正确、产物直连消费者端到端。消费者断言全用手工 fixture，生产者坏了它们照样绿；
     E 组补上写入侧的闭环。

用法：
  python evals/run_regression.py            # 全部
  python evals/run_regression.py --keep     # 保留临时目录便于排查
退出码：0 = 全过；1 = 有失败项
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SCRIPTS = os.path.join(ROOT, "scripts")
sys.path.insert(0, SCRIPTS)

RESULTS = []


def check(group, name, got, want):
    ok = got == want
    RESULTS.append((group, name, ok, got, want))
    print("  %s %-46s got=%-24s want=%s" % ("PASS" if ok else "FAIL", name, got, want))
    return ok


def run(script, *args):
    p = subprocess.run([sys.executable, os.path.join(SCRIPTS, script)] + list(args),
                       capture_output=True, text=True, encoding="utf-8", errors="replace")
    return (p.stdout or "") + (p.stderr or ""), p.returncode


def _run_code(script, *args):
    p = subprocess.run([sys.executable, os.path.join(SCRIPTS, script)] + list(args),
                       capture_output=True, text=True, encoding="utf-8", errors="replace")
    return p.returncode


def _fixture(tmp, name, report, bodies, report_subdir=None):
    d = os.path.join(tmp, name)
    shutil.rmtree(d, ignore_errors=True)
    os.makedirs(d)
    for fn, content in bodies.items():
        open(os.path.join(d, fn), "w", encoding="utf-8").write(content)
    if report is not None:
        rp = os.path.join(d, report_subdir, "_fetch_report.json") if report_subdir \
            else os.path.join(d, "_fetch_report.json")
        os.makedirs(os.path.dirname(rp), exist_ok=True)
        with open(rp, "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False)
    return d


# ---------------------------------------------------------------- A. 侧车判定重建
def test_hdr_verdict(tmp):
    import extract_endpoints as E
    print("\n[A] hdr_verdict —— 侧车判定重建")
    cases = [
        ("Status403_CL相符+BOM", "\ufeffStatus: 403\nContent-Length: %d\n", b"0123456789", "HTTP_403"),
        ("Status403_CL不符",     "Status: 403\nContent-Length: 9999\n",     b"0123456789", "HTTP_403"),
        ("Status200_CL相符",     "Status: 200\nContent-Length: 10\n",       b"0123456789", "OK"),
        ("Status200_截断",       "Status: 200\nContent-Length: 9999\n",     b"0123456789", "TRUNCATED"),
        ("Status200_无CL",       "Status: 200\nContent-Type: text/html\n",  b"0123456789", "CL_MISSING"),
        ("旧侧车_截断+BOM",      "\ufeffContent-Length: 9999\n",            b"0123456789", "TRUNCATED"),
        ("旧侧车_相符时不判",     "Content-Length: 10\n",                    b"0123456789", None),
        ("Status200_无CL_chunked", "Status: 200\nTransfer-Encoding: chunked\n", b"0123456789", "CHUNKED"),
        ("无侧车",               None,                                      b"0123456789", None),
    ]
    for i, (label, hdr, body, want) in enumerate(cases):
        p = os.path.join(tmp, "h%d.html" % i)
        open(p, "wb").write(body)
        if hdr is not None:
            open(p + ".hdr", "w", encoding="utf-8").write(hdr)
        check("A", label, E.hdr_verdict(p), want)


# ---------------------------------------------------------------- B. 判定联动
BAD_BODIES = {
    "errorpage.html": '<a href="/api/from-error-body/leak">x</a>',
    "good.js": 'var b={url:"/api/v1/real"}; // 密码 marker-okpass\n',
}


def test_exclusion(tmp):
    print("\n[B] 判定联动 —— 非 OK 文件不得用于提取（含三态与自身内容）")
    RPT = [{"file": "errorpage.html", "verdict": "HTTP_403"},
           {"file": "good.js", "verdict": "OK"}]

    # B1 正常报告
    d = _fixture(tmp, "b1", RPT, BAD_BODIES)
    out, rc = run("extract_endpoints.py", "--dir", d)
    check("B", "正常报告：403 页不进清单", "from-error-body" in out, False)
    check("B", "正常报告：正常接口保留", "api/v1/real" in out, True)
    check("B", "正常报告：退出码 0（非降级）", rc, 0)

    # B2 报告带 BOM
    d = _fixture(tmp, "b2", None, BAD_BODIES)
    open(os.path.join(d, "_fetch_report.json"), "w", encoding="utf-8-sig").write(json.dumps(RPT))
    out, _ = run("extract_endpoints.py", "--dir", d)
    check("B", "报告带 BOM：仍排除", "from-error-body" in out, False)

    # B3 报告损坏 + 侧车重建
    d = _fixture(tmp, "b3", None, BAD_BODIES)
    open(os.path.join(d, "_fetch_report.json"), "w", encoding="utf-8").write("broken json")
    for fn, st in (("errorpage.html", 403), ("good.js", 200)):
        p = os.path.join(d, fn)
        open(p + ".hdr", "w", encoding="utf-8-sig").write(
            "Status: %d\nContent-Length: %d\n" % (st, os.path.getsize(p)))
    out, _ = run("extract_endpoints.py", "--dir", d)
    check("B", "报告损坏+侧车：403 页不进清单", "from-error-body" in out, False)
    check("B", "报告损坏+侧车：正常接口保留", "api/v1/real" in out, True)
    check("B", "报告损坏：出声告警", "判定报告读取失败" in out, True)
    check("B", "报告损坏：退出码 1", _run_code("extract_endpoints.py", "--dir", d), 1)

    # B4 报告在子目录：与文件同处该子目录（safe_fetch 真实形态——报告与下载物同在 --out 目录；
    #     旧版 fixture 把文件放报告上级、靠裸文件名跨目录命中，恰是被修复的误杀机制）
    d = _fixture(tmp, "b4", None, {})
    os.makedirs(os.path.join(d, "dl"))
    for fn, c in BAD_BODIES.items():
        open(os.path.join(d, "dl", fn), "w", encoding="utf-8").write(c)
    with open(os.path.join(d, "dl", "_fetch_report.json"), "w") as f:
        json.dump(RPT, f)
    out, _ = run("extract_endpoints.py", "--dir", d)
    check("B", "报告在子目录：仍排除（同目录作用域）", "from-error-body" in out, False)
    check("B", "子目录报告：REPORT 只计一次", "REPORT×1" in out, True)

    # B5 三个脚本一致（正向+否定成对断言——否定只能证明没做错）
    d = _fixture(tmp, "b5", RPT, BAD_BODIES)
    out, _ = run("extract_apis.py", d)
    check("B", "extract_apis 同样排除 + 正常接口保留",
          ("from-error-body" in out, "/api/v1/real" in out), (False, True))
    out, _ = run("scan_comments.py", "--dir", d)
    check("B", "scan_comments 同样排除 + 正常线索保留",
          ("from-error-body" in out, "marker-okpass" in out), (False, True))
    broken = _fixture(tmp, "b5x", None, BAD_BODIES)
    open(os.path.join(broken, "_fetch_report.json"), "w", encoding="utf-8").write("bad{")
    out5x, code5x = run("scan_comments.py", "--dir", broken)
    check("B", "scan_comments 损坏报告：退出码1+告警+无崩溃",
          (code5x, "判定报告读取失败" in out5x, "Traceback" in out5x), (1, True, False))

    # B5b 多文件正向路径：钉"只扫每目录最后一个文件"的循环缩进退化
    #（两轮事故根因：否定断言只证明没做错，证明不了做成了——必须两个文件都在场）
    d = _fixture(tmp, "b5b", None, {"aaa_first.js": 'var a={url:"/api/from-file-A",method:"get"};',
                                    "zzz_last.js": 'var z={url:"/api/from-file-B",method:"get"};'})
    out, _ = run("extract_apis.py", d)
    check("B", "extract_apis 多文件全部被扫（非只最后一个）",
          ("from-file-A" in out, "from-file-B" in out), (True, True))

    # B6 --files 模式
    d = _fixture(tmp, "b6", RPT, BAD_BODIES)
    out, _ = run("extract_endpoints.py", "--files",
                 os.path.join(d, "errorpage.html"), os.path.join(d, "good.js"))
    check("B", "--files 模式：仍排除", "from-error-body" in out, False)

    # B7 无报告 = 正常态（外部来源文件）：静默 + 退出码 0 —— 与"损坏"严格区分
    d = _fixture(tmp, "b7", None, BAD_BODIES)
    out, rc = run("extract_endpoints.py", "--dir", d)
    check("B", "无报告：不告警（正常态）", "判定报告读取失败" in out, False)
    check("B", "无报告：退出码 0", rc, 0)

    # B8 判定报告自身内容不进提取（报告 JSON 里的 /api/ 前缀串不得变接口）
    rpt_trap = [{"file": "good.js", "verdict": "OK", "note": "/api/fake-from-report"}]
    d = _fixture(tmp, "b8", rpt_trap, {"good.js": 'var b={url:"/api/v1/real"};'})
    out, _ = run("extract_endpoints.py", "--dir", d)
    check("B", "报告自身内容不污染清单", "fake-from-report" in out, False)

    # B9 多站点同名文件：判定按目录作用域——A 站的坏判定不吃 B 站的好文件
    top = os.path.join(tmp, "b9")
    shutil.rmtree(top, ignore_errors=True)
    os.makedirs(os.path.join(top, "siteA"))
    os.makedirs(os.path.join(top, "siteB"))
    open(os.path.join(top, "siteA", "_fetch_report.json"), "w").write(
        json.dumps([{"file": "app.js", "verdict": "TRUNCATED"}]))
    open(os.path.join(top, "siteA", "app.js"), "w").write('var a={url:"/api/siteA/dead"};')
    open(os.path.join(top, "siteB", "_fetch_report.json"), "w").write(
        json.dumps([{"file": "app.js", "verdict": "OK"}]))
    open(os.path.join(top, "siteB", "app.js"), "w").write('var b={url:"/api/v1/siteB/real"};')
    out, _ = run("extract_endpoints.py", "--dir", top)
    check("B", "多站点同名：好文件不被他站坏判定误杀", "siteB/real" in out, True)
    check("B", "多站点同名：坏文件仍被本站判定排除", "siteA/dead" in out, False)

    # B10 CHUNKED 判定不排除（chunked 是传输形态不是缺陷——可提取）
    d = _fixture(tmp, "b10", [{"file": "ch.js", "verdict": "CHUNKED"},
                              {"file": "bad.js", "verdict": "TRUNCATED"}],
                 {"ch.js": 'var c={url:"/api/chunk-ok"};', "bad.js": 'var d={url:"/api/bad10"};'})
    out, _ = run("extract_endpoints.py", "--dir", d)
    check("B", "CHUNKED 判定：不排除（可用于提取）", ("chunk-ok" in out, "bad10" in out), (True, False))


# ---------------------------------------------------------------- C. 提取核心规则
def test_extract_rules(tmp):
    print("\n[C] 提取核心规则 —— 不得回归")
    def one(name, body):
        d = os.path.join(tmp, name)
        shutil.rmtree(d, ignore_errors=True)
        os.makedirs(d)
        open(os.path.join(d, "app.js"), "w", encoding="utf-8").write(body)
        csvp = os.path.join(d, "o.csv")
        out, _ = run("extract_endpoints.py", "--dir", d, "--hidden", "--csv", csvp)
        text = open(csvp, encoding="utf-8-sig").read() if os.path.isfile(csvp) else ""
        return out, text

    out, csv = one("c1",
                   'var a={url:"/a/".concat(t,"/b"),method:"post"};'
                   'var p={url:"/api/v1/order/query",methods:"post",data:{userId:1,tenantId:2}};'
                   'var c={url:"face/batchImport",method:"get"};')
    check("C", "占位符保留（不焊死伪路径）", "/a/{t}/b" in csv, True)
    check("C", "复数方法键 methods:", ",POST," in csv, True)
    check("C", "无前导斜杠补 '/'", "/face/batchImport" in csv, True)
    check("C", "参数名列提取", "userId" in csv and "tenantId" in csv, True)

    out, csv2 = one("c2", 'API_HOST = "https://api.x.com";'
                          'var u={url:API_HOST+"/user/list",method:"post"};')
    check("C", "{API_HOST} 占位符保名（非 {expr}）", "{expr}" not in csv2, True)
    check("C", "常量回填基址（https）", ",https://api.x.com,POST," in csv2, True)

    out, csv3 = one("c3", 'WS_HOST="wss://p.x.com";'
                          'var ws=new WebSocket(WS_HOST+"/ws/n");'
                          'var es=new EventSource("/sse/log");'
                          'var wl="wss://d.x.com/ws/y";'
                          'var g={operationName:"GetU"};')
    check("C", "wss scheme 常量回填", ",wss://p.x.com,WSS," in csv3, True)
    check("C", "四通道：ws/sse/wss字面量/graphql-op",
          all(s in csv3 for s in ("/ws/n", "/sse/log", "wss://d.x.com/ws/y", "graphql-op")), True)

    d2 = os.path.join(tmp, "c4")
    shutil.rmtree(d2, ignore_errors=True)
    os.makedirs(d2)
    open(os.path.join(d2, "u.html"), "w", encoding="utf-8").write(
        '<a href=/admin/unquoted>x</a><a href=rel/page?pg=2>y</a>')
    csvp2 = os.path.join(d2, "o.csv")
    run("extract_endpoints.py", "--dir", d2, "--csv", csvp2)
    csv4 = open(csvp2, encoding="utf-8-sig").read()
    check("C", "无引号 HTML 属性", "/admin/unquoted" in csv4, True)
    check("C", "HTML 相对路径补斜杠 + query 列", "/rel/page" in csv4 and "?pg=2" in csv4, True)

    d3 = os.path.join(tmp, "c5")
    shutil.rmtree(d3, ignore_errors=True)
    os.makedirs(d3)
    open(os.path.join(d3, "zh-CN.json"), "w", encoding="utf-8").write(
        '{"k":"/api/v1/i18n","r":"api/noslash/x"}')
    open(os.path.join(d3, "logo.png"), "wb").write(b"\x89PNG")
    csvp3 = os.path.join(d3, "o.csv")
    out5, _ = run("extract_endpoints.py", "--dir", d3, "--csv", csvp3)
    csv5 = open(csvp3, encoding="utf-8-sig").read()
    check("C", "JSON 语言包不被静默跳过", "/api/v1/i18n" in csv5, True)
    check("C", "JSON 无前导斜杠补 '/'", "/api/noslash/x" in csv5, True)
    check("C", "跳过计数可见", "跳过非文本 1 个" in out5, True)

    out6, _ = one("c6", "var nothing=1;")
    check("C", "0 命中可见性行", "0 命中文件 1 个" in out6, True)

    # 版本化路径归 B 级（'/v[0-9]' 曾当字面量 in——永远 False，版本路径全部降 C）
    import re as _re
    d10 = os.path.join(tmp, "c10")
    shutil.rmtree(d10, ignore_errors=True)
    os.makedirs(d10)
    open(os.path.join(d10, "app.js"), "w", encoding="utf-8").write('var v={url:"/portal/v2/page",method:"get"};')
    out10, _ = run("extract_apis.py", d10)
    segB = _re.search(r"### gradeB[\s\S]*?(?=### |$)", out10)
    check("C", "版本化路径归 B 级", bool(segB and "/portal/v2/page" in segB.group(0)), True)

    # REL 形态 classify 无 off-by-one（补斜杠曾致 after 窗口错位、call_site 判 bare）
    d11 = os.path.join(tmp, "c11")
    shutil.rmtree(d11, ignore_errors=True)
    os.makedirs(d11)
    open(os.path.join(d11, "app.js"), "w", encoding="utf-8").write('post("api/user/info",e);')
    out11, _ = run("extract_apis.py", d11)
    segCS = _re.search(r"### gradeA::call_site[\s\S]*?(?=### |$)", out11)
    check("C", "REL 形态判 call_site（无 off-by-one）", bool(segCS and "/api/user/info" in segCS.group(0)), True)

    # .map sourcesContent 去转义（直接扫 JSON 原文曾产出带 \" 尾巴的路径，去重键错位）
    d12 = os.path.join(tmp, "c12")
    shutil.rmtree(d12, ignore_errors=True)
    os.makedirs(d12)
    open(os.path.join(d12, "app.js.map"), "w", encoding="utf-8").write(
        json.dumps({"version": 3, "sources": ["a.js"],
                    "sourcesContent": ['var m={url:"/api/from-map-src",method:"get"};']}))
    csvp12 = os.path.join(d12, "o.csv")
    run("extract_endpoints.py", "--dir", d12, "--csv", csvp12)
    csv12 = open(csvp12, encoding="utf-8-sig").read()
    check("C", ".map sourcesContent 去转义提取",
          ("/api/from-map-src" in csv12, 'from-map-src\\"' in csv12), (True, False))

    # 裸域带尾斜杠：group(2)='/' 曾是真值绕过裸域检查，产出 接口路径='/' 的垃圾行
    d13 = os.path.join(tmp, "c13")
    shutil.rmtree(d13, ignore_errors=True)
    os.makedirs(d13)
    open(os.path.join(d13, "app.js"), "w", encoding="utf-8").write(
        'var a={url:"https://bare.example.com/",method:"get"};')
    csvp13 = os.path.join(d13, "o.csv")
    run("extract_endpoints.py", "--dir", d13, "--csv", csvp13)
    csv13 = open(csvp13, encoding="utf-8-sig").read()
    check("C", "裸域尾斜杠不产垃圾行（落剔除计数）", "bare.example.com" in csv13, False)

    # --site 生成时打标（归属不事后补填）
    d7 = os.path.join(tmp, "c7")
    shutil.rmtree(d7, ignore_errors=True)
    os.makedirs(d7)
    open(os.path.join(d7, "app.js"), "w", encoding="utf-8").write('var s={url:"/api/s7",method:"get"};')
    csvp7 = os.path.join(d7, "o.csv")
    run("extract_endpoints.py", "--dir", d7, "--site", "www.target.com", "--csv", csvp7)
    import csv as _csv
    rows7 = list(_csv.DictReader(open(csvp7, encoding="utf-8-sig")))
    check("C", "--site 透传打标（站点列）", rows7 and rows7[0].get("站点"), "www.target.com")

    # = 赋值形态的 hidden 命中（value_expr 曾只认冒号：漏掉或借用他键的值）
    d8 = os.path.join(tmp, "c8")
    shutil.rmtree(d8, ignore_errors=True)
    os.makedirs(d8)
    open(os.path.join(d8, "app.js"), "w", encoding="utf-8").write(
        'var uploadUrl = "/upload/direct/path";'
        'var exportUrl = "/export/sessionList";'
        'var cfg = { url: "/real/api/list", method: "get" };')
    csvp8 = os.path.join(d8, "o.csv")
    run("extract_endpoints.py", "--dir", d8, "--hidden", "--csv", csvp8)
    rows8 = list(_csv.DictReader(open(csvp8, encoding="utf-8-sig"))) \
        if os.path.isfile(csvp8) else []
    hid8 = {r["形态"]: r["接口路径"] for r in rows8}
    # 精确等值断言：子串匹配拦不住"值被缝进假路径仍含该子串"的污染（弱断言放行事故）
    check("C", "= 赋值 hidden 精确取值（语句边界，不吞后续语句）",
          (hid8.get("hidden:uploadUrl"), hid8.get("hidden:exportUrl")),
          ("/upload/direct/path", "/export/sessionList"))

    # 多行拼接赋值：ASI 续行启发（行尾运算符不停）+ 纯拼接运算符确定性还原
    #（"/upload/" + "multi/line" 的裸 + 是唯一解释的字符串拼接——曾标 {expr}，
    #  而占位符语义是"需填写的动态段"，会让阶段 3 拿必 404 的假路径探测）
    d8b = os.path.join(tmp, "c8b")
    shutil.rmtree(d8b, ignore_errors=True)
    os.makedirs(d8b)
    open(os.path.join(d8b, "app.js"), "w", encoding="utf-8").write(
        'var multiUrl = "/upload/" +\n    "multi/line";\nvar nextUrl = "/next/one";\n'
        'var mixUrl = "/mix/" + uid + "/tail";\n')
    csvp8b = os.path.join(d8b, "o.csv")
    run("extract_endpoints.py", "--dir", d8b, "--hidden", "--csv", csvp8b)
    rows8b = list(_csv.DictReader(open(csvp8b, encoding="utf-8-sig"))) \
        if os.path.isfile(csvp8b) else []
    hid8b = {r["形态"]: r["接口路径"] for r in rows8b}
    check("C", "拼接还原：纯 + 确定性连接、真动态段仍占位",
          (hid8b.get("hidden:multiUrl"), hid8b.get("hidden:nextUrl"),
           hid8b.get("hidden:mixUrl")),
          ("/upload/multi/line", "/next/one", "/mix/{uid}/tail"))

    # 绝对 URL 落清单（曾整条被当噪声丢——违反"域外接口只记录"承诺）
    d9 = os.path.join(tmp, "c9")
    shutil.rmtree(d9, ignore_errors=True)
    os.makedirs(d9)
    open(os.path.join(d9, "app.js"), "w", encoding="utf-8").write(
        'var a={url:"https://api.x.com/v2/absoluteList",method:"get"};')
    csvp9 = os.path.join(d9, "o.csv")
    run("extract_endpoints.py", "--dir", d9, "--csv", csvp9)
    csv9 = open(csvp9, encoding="utf-8-sig").read()
    check("C", "绝对 URL 落清单（域外基址标注需另行授权）",
          ("/v2/absoluteList" in csv9, ",https://api.x.com," in csv9, "需另行授权" in csv9),
          (True, True, True))

    # 去重键含基路径（曾按 路径+方法 吞掉不同绝对基址的同名路径——多租户静默丢失）
    d9b = os.path.join(tmp, "c9b")
    shutil.rmtree(d9b, ignore_errors=True)
    os.makedirs(d9b)
    open(os.path.join(d9b, "app.js"), "w", encoding="utf-8").write(
        'var a={url:"https://a.com/api/dup",method:"get"};'
        'var b={url:"https://b.com/api/dup",method:"get"};')
    csvp9b = os.path.join(d9b, "o.csv")
    run("extract_endpoints.py", "--dir", d9b, "--csv", csvp9b)
    rows9b = list(_csv.DictReader(open(csvp9b, encoding="utf-8-sig")))
    bases9b = sorted(r["基路径"] for r in rows9b if r["接口路径"] == "/api/dup")
    check("C", "双绝对基址同路径各自成行（不互吞）", bases9b, ["https://a.com", "https://b.com"])

    # 反查索引同路径并集聚合（字典推导曾后者覆盖前者——同路径多基址丢来源文件）
    d9c = os.path.join(tmp, "c9c")
    shutil.rmtree(d9c, ignore_errors=True)
    os.makedirs(d9c)
    open(os.path.join(d9c, "a.js"), "w", encoding="utf-8").write(
        'var a={url:"/api/dup",method:"get"};')
    open(os.path.join(d9c, "b.js"), "w", encoding="utf-8").write(
        'var b={url:"https://b.com/api/dup",method:"get"};')
    out9c, _ = run("extract_endpoints.py", "--dir", d9c)
    import re as _re2
    line = _re2.search(r"^\s*/api/dup ← .+$", out9c, _re2.M)
    check("C", "反查索引同路径两来源都在（并集不互吞）",
          bool(line and "a.js" in line.group(0) and "b.js" in line.group(0)), True)

    # HTML 页面路由保留（eval 实测抓出的 P1：任意点号启发式曾静默丢 .html 路由）
    dpr = os.path.join(tmp, "c_pr")
    shutil.rmtree(dpr, ignore_errors=True)
    os.makedirs(dpr)
    open(os.path.join(dpr, "i.html"), "w", encoding="utf-8").write(
        '<a href="admin/dashboard.html">d</a><a href=help/faq.html>f</a>'
        '<a href="/static/app.css">c</a>')
    csvp_pr = os.path.join(dpr, "o.csv")
    run("extract_endpoints.py", "--dir", dpr, "--csv", csvp_pr)
    rows_pr = list(_csv.DictReader(open(csvp_pr, encoding="utf-8-sig")))
    pr = {r["接口路径"]: r["可疑"] for r in rows_pr}
    check("C", ".html 页面路由保留并标注（css 仍排除）",
          ("/admin/dashboard.html" in pr and "/help/faq.html" in pr
           and "页面路由" in pr.get("/admin/dashboard.html", "")
           and "/static/app.css" not in pr), True)

    # 相对路径常量回填（API_HOST="/api/v2" 这类无 scheme 前缀）
    drc = os.path.join(tmp, "c_rc")
    shutil.rmtree(drc, ignore_errors=True)
    os.makedirs(drc)
    open(os.path.join(drc, "a.js"), "w", encoding="utf-8").write(
        'API_HOST="/api/v2";var u={url:API_HOST+"/order/x",method:"get"};')
    csvp_rc = os.path.join(drc, "o.csv")
    run("extract_endpoints.py", "--dir", drc, "--csv", csvp_rc)
    rc = {r["接口路径"]: r["基路径"] for r in _csv.DictReader(open(csvp_rc, encoding="utf-8-sig"))}
    check("C", "相对路径常量回填基址", rc.get("/order/x"), "/api/v2")

    # 裸 fetch("/api/...") 首参字面量（.vue 高发盲区——axios/this.http 正则不覆盖，eval 实测 0 命中）
    dff = os.path.join(tmp, "c_ff")
    shutil.rmtree(dff, ignore_errors=True)
    os.makedirs(dff)
    open(os.path.join(dff, "admin.vue"), "w", encoding="utf-8").write(
        '<template><div>x</div></template>\n<script>fetch("/api/vue/fetchX?k=1")</script>')
    csvp_ff = os.path.join(dff, "o.csv")
    run("extract_endpoints.py", "--dir", dff, "--csv", csvp_ff)
    ff = {r["接口路径"]: (r["形态"], r["query"]) for r in _csv.DictReader(open(csvp_ff, encoding="utf-8-sig"))}
    check("C", "裸 fetch 首参字面量提取（.vue）",
          ff.get("/api/vue/fetchX"), ("fetch", "?k=1"))

    # 通道健康直方图：零也在场（裸 fetch 盲区修复前 fetch 恒 0 而无人看见）
    dch = os.path.join(tmp, "c_ch")
    shutil.rmtree(dch, ignore_errors=True)
    os.makedirs(dch)
    open(os.path.join(dch, "a.js"), "w", encoding="utf-8").write(
        'var u={url:"/api/only/url",method:"get"};')
    outch, _ = run("extract_endpoints.py", "--dir", dch, "--log",
                   os.path.join(dch, "r.txt"))
    logch = open(os.path.join(dch, "r.txt"), encoding="utf-8").read()
    check("C", "通道直方图：在场且零通道可见",
          ("通道命中直方图" in logch and "url 1" in logch
           and "fetch 0" in logch and "graphql 0" in logch), True)

    # 粗筛/精提对账：bare 调用点字符串（粗筛抓到、精提各通道全漏）必须被点名
    dre = os.path.join(tmp, "c_re")
    shutil.rmtree(dre, ignore_errors=True)
    os.makedirs(dre)
    open(os.path.join(dre, "app.js"), "w", encoding="utf-8").write(
        'post("api/user/info",e);var ok={url:"/api/known/one",method:"get"};')
    finep = os.path.join(dre, "fine.csv")
    run("extract_endpoints.py", "--dir", dre, "--csv", finep)
    outre, _ = run("extract_apis.py", dre, "--reconcile-fine", finep)
    check("C", "粗筛/精提对账点名盲区候选",
          ("粗筛有/精提无 1 条" in outre and "/api/user/info" in outre
           and "/api/known/one" not in outre.split("粗筛有/精提无")[1]), True)


# ---------------------------------------------------------------- D. 注释扫描
def test_comments(tmp):
    print("\n[D] 注释扫描 —— 命中 / 噪声 / 置信 / 证据本体")
    d = os.path.join(tmp, "d1")
    shutil.rmtree(d, ignore_errors=True)
    os.makedirs(d)
    open(os.path.join(d, "app.js"), "w", encoding="utf-8").write(
        '/*! lib v1 | (c) 2024 Corp | Licensed under the MIT License. */\n'
        '// 测试账号 admin  密码：Admin@123\n'
        '// 旧接口已下线: /api/v1/legacyUserList\n'
        '// 内网备份机 10.20.30.40:8080 与 gw.corp\n'
        'var ua="Mozilla/5.0"; // 版本号 172.20.5.5 是伪装串\n')
    out, _ = run("scan_comments.py", "--dir", d)
    check("D", "中文凭据命中", "Admin@123" in out, True)
    check("D", "注释旧接口命中", "/api/v1/legacyUserList" in out, True)
    check("D", "内网地址命中", "10.20.30.40:8080" in out, True)
    check("D", "license 块滤除", "lib v1" not in out and "(c) 2024" not in out, True)
    check("D", "172.20 判低置信", "172.20.5.5" in out and "低置信" in out, True)

    d2 = os.path.join(tmp, "d2")
    shutil.rmtree(d2, ignore_errors=True)
    os.makedirs(d2)
    open(os.path.join(d2, "Page.vue"), "w", encoding="utf-8").write(
        "<template><!-- 隐藏入口 /api/v2/hiddenAdmin --></template>\n"
        "<script>// 密码 vueSecret99</script>")
    out2, _ = run("scan_comments.py", "--dir", d2)
    check("D", "Vue 模板+脚本双区命中",
          "/api/v2/hiddenAdmin" in out2 and "vueSecret99" in out2, True)

    # Vue 模板属性里的 // 不当 JS 注释切假线索（JS 正则仅限 <script> 区间）
    d2v = os.path.join(tmp, "d2v")
    shutil.rmtree(d2v, ignore_errors=True)
    os.makedirs(d2v)
    open(os.path.join(d2v, "P.vue"), "w", encoding="utf-8").write(
        '<template><a href="//cdn.example.com/x" title="// 密码 fakeTpl88">t</a></template>\n'
        "<script>// 密码 realVue77</script>")
    outv, _ = run("scan_comments.py", "--dir", d2v)
    check("D", "Vue 模板 // 不产假线索（JS 注释仅限 script 区）",
          ("fakeTpl88" in outv, "realVue77" in outv), (False, True))

    # 内容嗅探：.js 形态的 HTML 错误页（重定向落盘等）按 HTML 注释扫——与精提同口径
    d8 = os.path.join(tmp, "d8")
    shutil.rmtree(d8, ignore_errors=True)
    os.makedirs(d8)
    open(os.path.join(d8, "err.js"), "w", encoding="utf-8").write(
        "<!doctype html><html><!-- 密码 sniffed99 --></html>")
    out8, _ = run("scan_comments.py", "--dir", d8)
    check("D", ".js 形态 HTML 内容按 HTML 注释扫（嗅探）", "sniffed99" in out8, True)

    # 证据本体：license 后紧跟多行块——上下文必须夹在块内、换行显式 ⏎、license 不倒灌
    d3 = os.path.join(tmp, "d3")
    shutil.rmtree(d3, ignore_errors=True)
    os.makedirs(d3)
    open(os.path.join(d3, "blk.js"), "w", encoding="utf-8").write(
        '/*! @license MIT-Lic (c) 2020 */\n'
        '/*\n * 行2：账号 blkadmin\n * 行3：密码 BlkPass@9\n */\n')
    out3, _ = run("scan_comments.py", "--dir", d3)
    tail = out3.split("线索", 1)[1] if "线索" in out3 else out3
    check("D", "证据本体：⏎ 标记 + license 不倒灌",
          "⏎" in tail and "MIT-Lic" not in tail and "行2：账号 blkadmin" in tail, True)

    # 置信只升不降：同值两语境（网关 + 版本号）合并为高
    d4 = os.path.join(tmp, "d4")
    shutil.rmtree(d4, ignore_errors=True)
    os.makedirs(d4)
    open(os.path.join(d4, "f1.js"), "w", encoding="utf-8").write("// 网关出口 172.30.9.9\n")
    open(os.path.join(d4, "f2.js"), "w", encoding="utf-8").write("// 版本号 172.30.9.9\n")
    out4, _ = run("scan_comments.py", "--dir", d4)
    check("D", "同值多语境置信只升不降", "高置信] 172.30.9.9" in out4 and "×2" in out4, True)

    d5 = os.path.join(tmp, "d5")
    shutil.rmtree(d5, ignore_errors=True)
    os.makedirs(d5)
    open(os.path.join(d5, "a.json"), "w").write('{"x":1}')
    open(os.path.join(d5, "b.js.map"), "w").write('{"version":3}')
    open(os.path.join(d5, "c.js"), "w").write("// 密码 c9x\n")
    out5, _ = run("scan_comments.py", "--dir", d5)
    check("D", "JSON/map 跳过计数（措辞含两类）", "JSON/map 类无注释语法跳过 2 个" in out5, True)

    # 五段数字串不误报内网（10.1.2.3.4 曾被部分匹配成 10.1.2.3）
    d6 = os.path.join(tmp, "d6")
    shutil.rmtree(d6, ignore_errors=True)
    os.makedirs(d6)
    open(os.path.join(d6, "v.js"), "w", encoding="utf-8").write("// 版本串 10.1.2.3.4 五段\n")
    out6, _ = run("scan_comments.py", "--dir", d6)
    check("D", "五段数字串不误报内网", "内网裸地址" in out6, False)


# ---------------------------------------------------------------- E. 生产者契约
def test_safe_fetch_contract(tmp):
    print("\n[E] safe_fetch 生产者契约（本地回环 HTTP 服务，零外网）")
    import http.server
    import threading

    OK_BODY = b'var e={url:"/api/e2e",method:"get"};'
    DENY_BODY = b"<a href=/from-e2e-403>x</a>"
    CHUNK_BODY = b'var k={url:"/api/chunked9",method:"get"};'

    class H(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"               # chunked 传输需要 1.1

        def do_GET(self):
            if self.path.startswith("/ok"):
                body, code = OK_BODY, 200
            elif self.path.startswith("/denied"):
                body, code = DENY_BODY, 403
            elif self.path.startswith("/redir"):   # 重定向链留证用：301 → /ok.js
                self.send_response(301)
                self.send_header("Location", "/ok.js")
                self.end_headers()
                return
            elif self.path.startswith("/a/app"):    # 跨轮重名漂移用：a/b 两源同名 app.js
                body, code = b"//content-A", 200
            elif self.path.startswith("/b/app"):
                body, code = b"//content-B", 200
            elif self.path.startswith("/chk"):      # chunked：无 CL 的传输形态
                self.send_response(200)
                self.send_header("Transfer-Encoding", "chunked")
                self.end_headers()
                self.wfile.write(b"%x\r\n%s\r\n0\r\n\r\n" % (len(CHUNK_BODY), CHUNK_BODY))
                return
            else:                                   # 无 Content-Length → CL_MISSING
                body, code = b"var n=1;", 200
                self.send_response(code)
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(body)
                return
            self.send_response(code)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        d = os.path.join(tmp, "e1")
        os.makedirs(d)
        open(os.path.join(d, "urls.txt"), "w").write("/ok.js\n/denied.html\n/nocl.js\n/chk.js\n")
        run("safe_fetch.py", "--base", "http://127.0.0.1:%d" % port,
            "--urls", os.path.join(d, "urls.txt"), "--out", os.path.join(d, "dl"),
            "--timeout", "5", "--retry", "1")

        hdr_ok = open(os.path.join(d, "dl", "ok.js.hdr"), encoding="utf-8-sig").read()
        check("E", "safe_fetch 侧车首行写 Status", hdr_ok.splitlines()[0].strip(), "Status: 200")

        rpt = json.load(open(os.path.join(d, "dl", "_fetch_report.json"), encoding="utf-8-sig"))
        vmap = {os.path.basename(r["file"]): r["verdict"] for r in rpt}
        check("E", "报告判定：OK / HTTP_403 / CL_MISSING",
              (vmap.get("ok.js"), vmap.get("denied.html"), vmap.get("nocl.js")),
              ("OK", "HTTP_403", "CL_MISSING"))

        check("E", "下载字节完整", open(os.path.join(d, "dl", "ok.js"), "rb").read(), OK_BODY)
        check("E", "chunked 传输 → CHUNKED（可提取非缺陷）", vmap.get("chk.js"), "CHUNKED")
        check("E", "chunked 字节完整", open(os.path.join(d, "dl", "chk.js"), "rb").read(), CHUNK_BODY)

        out, _ = run("extract_endpoints.py", "--dir", os.path.join(d, "dl"))
        check("E", "真实产物直连消费者：403 不进清单、OK 保留",
              ("from-e2e-403" in out, "/api/e2e" in out), (False, True))

        # 二跳补抓 = 同一 --out 跑第二轮：判定报告必须合并保留（曾"w"整写丢第一轮判定）
        open(os.path.join(d, "urls2.txt"), "w").write("/ok2.js\n")
        run("safe_fetch.py", "--base", "http://127.0.0.1:%d" % port,
            "--urls", os.path.join(d, "urls2.txt"), "--out", os.path.join(d, "dl"),
            "--timeout", "5", "--retry", "1")
        rpt2 = json.load(open(os.path.join(d, "dl", "_fetch_report.json"), encoding="utf-8-sig"))
        vmap2 = {os.path.basename(r["file"]): r["verdict"] for r in rpt2}
        check("E", "分批下载两轮：判定报告合并保留",
              (vmap2.get("ok2.js"), vmap2.get("ok.js"), vmap2.get("denied.html")),
              ("OK", "OK", "HTTP_403"))

        # 跨轮重名漂移：第三轮下 /a/app.js + /b/app.js（b 改名 app__b.js），
        # 第四轮只下 /b/app.js——不得占裸名覆盖 a 的磁盘内容，报告 (file,url) 与磁盘一致
        baseu = "http://127.0.0.1:%d" % port
        open(os.path.join(d, "u3.txt"), "w").write("/a/app.js\n/b/app.js\n")
        run("safe_fetch.py", "--base", baseu, "--urls", os.path.join(d, "u3.txt"),
            "--out", os.path.join(d, "dl"), "--timeout", "5", "--retry", "1")
        open(os.path.join(d, "u4.txt"), "w").write("/b/app.js\n")
        run("safe_fetch.py", "--base", baseu, "--urls", os.path.join(d, "u4.txt"),
            "--out", os.path.join(d, "dl"), "--timeout", "5", "--retry", "1")
        rpt3 = json.load(open(os.path.join(d, "dl", "_fetch_report.json"), encoding="utf-8-sig"))
        pairs3 = {(r["file"], r["url"]) for r in rpt3}
        open(os.path.join(d, "u5.txt"), "w").write("/redir.js\n")
        run("safe_fetch.py", "--base", baseu, "--urls", os.path.join(d, "u5.txt"),
            "--out", os.path.join(d, "dl"), "--timeout", "5", "--retry", "1")
        hdr_redir = open(os.path.join(d, "dl", "redir.js.hdr"), encoding="utf-8-sig").read()
        check("E", "重定向最终地址留证（.hdr Effective-URL）",
              ("Effective-URL" in hdr_redir and "/ok.js" in hdr_redir,
               open(os.path.join(d, "dl", "redir.js"), "rb").read() == OK_BODY),
              (True, True))

        check("E", "跨轮重名：不覆盖他轮文件、报告与磁盘一致",
              (open(os.path.join(d, "dl", "app.js"), "rb").read(),
               open(os.path.join(d, "dl", "app__b.js"), "rb").read(),
               ("app.js", baseu + "/a/app.js") in pairs3,
               ("app__b.js", baseu + "/b/app.js") in pairs3),
              (b"//content-A", b"//content-B", True, True))
    finally:
        srv.shutdown()


def test_mine_responses(tmp):
    print("\n[F] mine_responses —— 响应体挖掘（零请求 + 待批准门控）")
    import csv as _csv

    d = os.path.join(tmp, "f1")
    shutil.rmtree(d, ignore_errors=True)
    os.makedirs(d)
    # 五模式 fixture
    open(os.path.join(d, "a.body"), "w", encoding="utf-8").write(
        '{"path":"/api/echo/path"}')                                      # error_echo
    open(os.path.join(d, "b.body"), "w", encoding="utf-8").write(
        '{"links":{"next":"/api/hateoas/next","related":"/api/hateoas/rel"}}')  # hateoas
    open(os.path.join(d, "c.body"), "w", encoding="utf-8").write(
        '{"upload_url":"/api/upload/here","safe_url":"/api/safe/one"}')  # url_field
    open(os.path.join(d, "d.body"), "w", encoding="utf-8").write(
        '{"data":"/api/path/value","other":"not a path"}')               # path_value
    open(os.path.join(d, "e.body"), "w", encoding="utf-8").write(
        '{"ref":"/users/123/orders"}')                                   # nested_uri
    # 危险词 fixture
    open(os.path.join(d, "f.body"), "w", encoding="utf-8").write(
        '{"x":"/api/export/run","y":"/api/delete/it","z":"/api/info/list"}')

    csvp = os.path.join(d, "mined.csv")
    run("mine_responses.py", "--dir", d, "--csv", csvp, "--log", os.path.join(d, "r.txt"))
    rpt = open(os.path.join(d, "r.txt"), encoding="utf-8").read()
    rows = list(_csv.DictReader(open(csvp, encoding="utf-8-sig")))

    paths = {r["接口路径"] for r in rows}
    check("F", "五模式正向命中",
          ("/api/echo/path" in paths and "/api/hateoas/next" in paths
           and "/api/upload/here" in paths and "/api/path/value" in paths
           and "/users/{id}/orders" in paths), True)
    check("F", "危险词标记", 
          any(r["风险"] == "⚠高危" for r in rows if r["接口路径"] == "/api/export/run")
          and any(r["风险"] == "⚠高危" for r in rows if r["接口路径"] == "/api/delete/it")
          and any(not r["风险"] for r in rows if r["接口路径"] == "/api/info/list"), True)
    check("F", "全部条目状态=待批准",
          all(r["状态"] == "待批准" for r in rows), True)
    check("F", "报告含'不自动进入验证'警告",
          "不自动进入验证" in rpt or "须用户点名" in rpt, True)
    check("F", "报告含高危汇总区",
          "高危条目" in rpt, True)

    # 去重：先造一份入口清单，再跑一次确认不重复入
    entry_csv = os.path.join(d, "entry.csv")
    with open(entry_csv, "w", encoding="utf-8-sig", newline="") as f:
        w = _csv.DictWriter(f, fieldnames=["URL", "方法", "参数", "来源", "状态", "验证结果", "备注"])
        w.writeheader()
        w.writerow({"URL": "/api/echo/path", "方法": "GET", "参数": "", "来源": "JS提取",
                    "状态": "已验证", "验证结果": "需凭据", "备注": ""})
    csvp2 = os.path.join(d, "mined2.csv")
    run("mine_responses.py", "--dir", d, "--entry-list", entry_csv,
        "--csv", csvp2, "--log", os.path.join(d, "r2.txt"))
    rows2 = list(_csv.DictReader(open(csvp2, encoding="utf-8-sig")))
    check("F", "已有条目去重（不重复发现）",
          "/api/echo/path" not in {r["接口路径"] for r in rows2}, True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--keep", action="store_true", help="保留临时目录")
    args = ap.parse_args()

    tmp = tempfile.mkdtemp(prefix="wrm_regress_")
    print("临时目录：%s" % tmp)
    try:
        test_hdr_verdict(tmp)
        test_exclusion(tmp)
        test_extract_rules(tmp)
        test_comments(tmp)
        test_safe_fetch_contract(tmp)
    finally:
        if not args.keep:
            shutil.rmtree(tmp, ignore_errors=True)

    # ================================================================ F. 响应体挖掘
    test_mine_responses(tmp)

    # 文档一致性静态检查（P3 族漂移的机械防线）：作为闸门最后一项——
    # 跨文件引用失效/词表多处定义/数字复制/形态映射缺项都会让回归变红
    import subprocess as _sp
    cc = _sp.run([sys.executable, os.path.join(HERE, "check_consistency.py")],
                 capture_output=True, text=True, encoding="utf-8", errors="replace")
    print(cc.stdout.rstrip())
    check("META", "文档一致性静态检查（9 项）全过", cc.returncode, 0)

    bad = [r for r in RESULTS if not r[2]]
    print("\n" + "=" * 64)
    print("回归结果：%d/%d 通过" % (len(RESULTS) - len(bad), len(RESULTS)))
    if bad:
        print("失败项：")
        for g, n, _, got, want in bad:
            print("  [%s] %s  got=%s want=%s" % (g, n, got, want))
    print("=" * 64)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
