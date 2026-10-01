#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
safe_fetch.py —— 带「完整性校验 + 退避重试」的资源下载器
应对 references/environment-and-pitfalls.md 假象表 #1（连通抖动）与 #4（静默截断）；完整性判定口径见 delivery.md §0。

核心：curl/wget/urllib 都【不会】在截断时报错（HTTP 200 + exit 0，只是字节数少）。
      必须自己拿 Content-Length 与实收字节数比对，才算"拿到了"。

用法：
  python safe_fetch.py --base https://host --proxy http://127.0.0.1:8080 \
      --urls urls.txt --out ./dl --retry 6 --ua chrome

  urls.txt 每行一个路径（/static/js/app.js）或完整 URL。
  输出：文件本体 + 每个文件的 .hdr，以及末尾的判定表（OK / TRUNCATED / CL_MISSING / FAILED /
        HTTP_<状态码>，如 HTTP_403——响应完整但非成功，4xx 为确定性结果不重试）。
"""
import argparse, os, re, ssl, sys, time, json
import urllib.request, urllib.error

# 统一 UTF-8 输出：Windows 控制台默认 GBK，中文会乱码
for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

UA_CHROME = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
             "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36")


def build_opener(proxy):
    handlers = []
    if proxy:
        handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
        # 仅走代理时关校验（Yakit/Burp 自签 CA）；直连保持默认校验——
        # 浏览器 UA + 无条件 CERT_NONE 在敌意网络下结果可被注入
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        handlers.append(urllib.request.HTTPSHandler(context=ctx))
    else:
        handlers.append(urllib.request.ProxyHandler({}))          # 显式禁用环境代理，TLS 默认校验
    return urllib.request.build_opener(*handlers)


def fetch_once(opener, url, ua, timeout):
    req = urllib.request.Request(url, headers={
        "User-Agent": ua,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
    })
    try:
        with opener.open(req, timeout=timeout) as r:
            body = r.read()
            cl = r.headers.get("Content-Length")
            hdrs = dict(r.headers)
            final = r.geturl()                          # 跟随重定向后的最终地址
            if final and final != url:
                # 重定向链证据：.hdr 只存最终响应头，链信息会丢——伪头留证
                hdrs["Effective-URL"] = final
            return r.status, body, (int(cl) if cl and cl.isdigit() else None), hdrs
    except urllib.error.HTTPError as e:
        # 非 2xx 会抛异常，但 e 本身就是响应对象 —— 必须区分"404 不存在"与"网络失败"，
        # 否则会把 L3/L4 里最重要的判据（存在性）丢掉。
        body = e.read() if hasattr(e, "read") else b""
        cl = e.headers.get("Content-Length") if e.headers else None
        hdrs = dict(e.headers or {})
        try:
            final = e.geturl()
            if final and final != url:
                hdrs["Effective-URL"] = final
        except Exception:
            pass
        return e.code, body, (int(cl) if cl and str(cl).isdigit() else None), hdrs


def safe_fetch(opener, url, dest, ua, retry, timeout, verbose=True):
    """返回 dict：verdict / status / size / cl / tries / note"""
    best = {"verdict": "FAILED", "status": None, "size": 0, "cl": None, "tries": 0}
    os.makedirs(os.path.dirname(os.path.abspath(dest)), exist_ok=True)
    for i in range(1, retry + 1):
        best["tries"] = i
        try:
            st, body, cl, hdrs = fetch_once(opener, url, ua, timeout)
        except Exception as e:
            best.update(status=None, note="%s: %s" % (type(e).__name__, e))
            if verbose:
                print("    try%d  %s" % (i, best["note"]))
            time.sleep(min(1.0 * i, 4))                            # 线性退避
            continue

        size = len(body)
        best.update(status=st, size=size, cl=cl)

        # 写盘 + 留头，便于事后复核
        with open(dest, "wb") as f:
            f.write(body)
        with open(dest + ".hdr", "w", encoding="utf-8", errors="replace") as f:
            # 首行写状态码：侧车自包含——判定报告损坏时，提取器可从 .hdr 完整重建
            # verdict（Status≠200→HTTP_4xx；CL 不符→TRUNCATED），不依赖 urllib 头部行为
            f.write("Status: %d\n" % st)
            for k, v in hdrs.items():
                f.write("%s: %s\n" % (k, v))

        if st != 200:
            best["verdict"] = "HTTP_%d" % st                      # 可能是 WAF 拦截，不是"文件不存在"
        elif cl is None:
            te = (hdrs.get("Transfer-Encoding") or hdrs.get("transfer-encoding") or "")
            if "chunked" in te.lower() and size > 0:
                best["verdict"] = "CHUNKED"    # chunked 是传输形态不是缺陷：完整已收，只是无 CL 可校验
            else:
                best["verdict"] = "CL_MISSING"                    # 服务端没给长度 → 无法自证，人工确认
        elif size != cl:
            best["verdict"] = "TRUNCATED"                          # ★ 就是这一类最坑
        else:
            best["verdict"] = "OK"

        if verbose:
            print("    try%d  %s size=%s cl=%s" % (i, best["verdict"], size, cl))

        # 性能：4xx 是确定性结果（除 408/429），重试毫无意义 → 立即返回，省掉后面几次退避睡眠
        if 400 <= st < 500 and st not in (408, 429):
            return best
        if best["verdict"] in ("OK", "CHUNKED"):   # chunked 重试也不会长出 CL，同样确定性
            return best
        time.sleep(min(1.0 * i, 4))
    return best


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="", help="基础地址，如 https://host")
    ap.add_argument("--urls", required=True, help="URL/路径清单文件，每行一个")
    ap.add_argument("--out", default="./dl", help="输出目录")
    ap.add_argument("--proxy", default="", help="代理，如 http://127.0.0.1:8080")
    ap.add_argument("--retry", type=int, default=6)
    ap.add_argument("--timeout", type=int, default=90)
    ap.add_argument("--ua", default="chrome", choices=["chrome", "raw"],
                    help="raw 会暴露非浏览器 UA —— websaas 类 WAF 会全拦，慎用")
    ap.add_argument("--gap", type=float, default=1.0, help="文件之间的间隔秒数")
    ap.add_argument("--log", help="把全部输出改写到该文件（UTF-8）。"
                                  "PowerShell 管道会用 GBK 解码子进程 stdout 导致中文乱码，"
                                  "需要中文输出时用它")
    args = ap.parse_args()

    if args.log:
        sys.stdout = open(args.log, "w", encoding="utf-8")

    ua = UA_CHROME if args.ua == "chrome" else "python-urllib/safe_fetch"
    opener = build_opener(args.proxy or None)

    urls = [x.strip() for x in open(args.urls, encoding="utf-8") if x.strip()]
    rows = []
    used_names = {}                                     # 平铺写出的重名会互相覆盖 + 判定错乱
    # 跨轮初始化：--out 的命名空间在两轮间持久，改名决策不能只看本轮——
    # 否则第二轮只下 /b/app.js 会占裸名 app.js，覆盖第一轮 /a/app.js 的磁盘内容，
    # 而合并报告仍保留 ("app.js", /a/) 行，报告与磁盘说谎性不一致（实测事故）。
    # 旧报告给 file→url（同 URL 重下保名）；报告外的现存文件按未知来源占用。
    if os.path.isdir(args.out):
        _old_url = {}
        try:
            with open(os.path.join(args.out, "_fetch_report.json"), encoding="utf-8-sig") as f:
                for row in json.load(f):
                    if isinstance(row, dict) and row.get("file"):
                        _old_url[row["file"]] = row.get("url")
        except Exception:
            pass
        for fn in os.listdir(args.out):
            used_names[fn] = _old_url.get(fn, "<<existing>>")
    for u in urls:
        full = u if u.startswith("http") else (args.base.rstrip("/") + "/" + u.lstrip("/"))
        src_path = full.split("?")[0]
        name = os.path.basename(src_path) or "index.html"
        if used_names.get(name) not in (None, full):
            stem, ext = os.path.splitext(name)
            parent = os.path.basename(os.path.dirname(src_path).rstrip("/")) or "root"
            parent = "".join(c if (c.isalnum() or c in "-_.") else "_" for c in parent)
            cand, k = "%s__%s%s" % (stem, parent, ext), 2
            while used_names.get(cand) not in (None, full):
                cand = "%s__%s_%d%s" % (stem, parent, k, ext)
                k += 1
            print("  ⚠ 重名冲突：%s → %s（%s 已被 %s 占用）" % (name, cand, name, used_names[name]))
            name = cand
        used_names[name] = full
        print("[*] %s" % full)
        r = safe_fetch(opener, full, os.path.join(args.out, name), ua, args.retry, args.timeout)
        r["url"] = full
        r["file"] = name
        rows.append(r)
        time.sleep(args.gap)

    print("\n===== 判定表 =====")
    print("%-9s %-6s %-10s %-10s %-6s  %s" % ("verdict", "http", "size", "cl", "tries", "file"))
    for r in rows:
        print("%-9s %-6s %-10s %-10s %-6s  %s" % (
            r["verdict"], r["status"], r["size"], r["cl"], r["tries"], r["file"]))

    # 分类收口：确定性失败（4xx）与"需重抓"必须分开说，否则会误导成"再试就行"
    ok = [r for r in rows if r["verdict"] == "OK"]
    chunked = [r for r in rows if r["verdict"] == "CHUNKED"]
    det = [r for r in rows if str(r["verdict"]).startswith("HTTP_4")]
    retry = [r for r in rows if r["verdict"] in ("TRUNCATED", "FAILED", "CL_MISSING")]
    print("")
    print("完整 %d/%d；chunked 不可校验(可用于提取) %d；确定性失败(4xx，重试无用) %d；需重抓/换窗口 %d"
          % (len(ok), len(rows), len(chunked), len(det), len(retry)))
    if chunked:
        print("  chunked（无 CL 的传输形态，非缺陷——可用于提取，产物标注不可校验）：%s"
              % ", ".join(r["file"] for r in chunked))
    if det:
        print("  4xx（多为 404 不存在 或 WAF 拦截，别当网络问题）：%s"
              % ", ".join("%s=%s" % (r["file"], r["verdict"]) for r in det))
    if retry:
        print("  需处理：%s" % ", ".join("%s=%s" % (r["file"], r["verdict"]) for r in retry))
    if not retry and not det:
        print("  ✅ 全部完整" + ("（%d 个 chunked 不可校验）" % len(chunked) if chunked else ""))
    # 判定报告 read-modify-write：二跳补抓就是往同一 --out 目录跑第二轮（phase2 §2 规定工作流），
    # "w" 整写会让第一轮的判定凭空消失——残缺文件静默回到提取范围。按 (file, url) 合并保留。
    rpt_path = os.path.join(args.out, "_fetch_report.json")
    merged = {}
    if os.path.isfile(rpt_path):
        try:
            with open(rpt_path, encoding="utf-8-sig") as f:
                for row in json.load(f):
                    if isinstance(row, dict) and row.get("file"):
                        merged[(row["file"], row.get("url"))] = row
        except Exception as e:
            print("⚠ 旧判定报告读取失败（%s），已丢弃重建——历史判定不保留" % e)
    for r in rows:
        merged[(r["file"], r["url"])] = r            # 同键以本轮为准（重下同一文件覆盖旧判定）
    with open(rpt_path, "w", encoding="utf-8") as f:
        json.dump(list(merged.values()), f, ensure_ascii=False, indent=1)
    if len(merged) > len(rows):
        print("（判定报告合并历史：%d 行 = 本轮 %d + 保留 %d）"
              % (len(merged), len(rows), len(merged) - len(rows)))
    sys.exit(0 if (not retry and not det) else 1)


if __name__ == "__main__":
    main()
