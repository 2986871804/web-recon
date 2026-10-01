#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
yakit_db_probe.py —— 只读复盘 Yakit 流量库（不依赖 MCP）
应对 references/environment-and-pitfalls.md 假象表 #6（流量混噪，先按 host 分组）与 #2（限速窗口）。

为什么需要它：
  · Yakit MCP 端口 LISTENING ≠ WorkBuddy 已把它注册进会话；工具检索不到时别反复重试，
    直接只读挂载同一个 SQLite —— 数据等价、零网络、零写入。

两个必踩的解析坑（本脚本已处理）：
  1. http_flows.response / request 是【被 JSON 转义过的字符串】（首字符是 "，\\r\\n 是字面量）
     → 必须先 json.loads() 反转义，否则切头身全失败、body 全空。
  2. http_flows.host 存在脏数据（被写成 SHA1 之类的字符串）→ 按 host 分组时必须容错。

用法：
  python yakit_db_probe.py --list                 # 按 host 分组统计（先做这一步再谈发现）
  python yakit_db_probe.py --host <目标域>        # 只看目标域，并给出状态码分布
  python yakit_db_probe.py --dump <flow_id>       # 打印某条流量的请求/响应（已反转义）
"""
import argparse, collections, json, os, sqlite3, sys

# 统一 UTF-8 输出：Windows 控制台默认 GBK，中文会乱码（重定向到文件后更明显）
for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

DEFAULT_DBS = [
    os.path.join(os.path.expanduser("~"), "Yakit", "Yakit", "yakit-projects", "default-yakit.db"),
    os.path.join(os.path.expanduser("~"), "Yakit", "yakit-projects", "default-yakit.db"),
]


def pick_db(explicit=None):
    if explicit:
        return explicit
    cands = [p for p in DEFAULT_DBS if os.path.exists(p)]
    if not cands:
        sys.exit("找不到 Yakit 库，请用 --db 指定")
    return max(cands, key=os.path.getmtime)          # 取最近写入的那个


def warn_if_empty(con, path):
    """Yakit 支持多项目库，用户也可能主动清空历史 —— 选中的库为空时给出下一步。"""
    try:
        n = con.execute("SELECT COUNT(*) FROM http_flows WHERE deleted_at IS NULL").fetchone()[0]
    except Exception as e:
        print("[!] 无法统计 http_flows：%r" % e)
        return
    if n:
        return
    print("[!] 当前库 http_flows = 0。可能原因：① 用户主动清空了历史；② 切到了另一个项目库。")
    print("    其他候选库：")
    for p in DEFAULT_DBS:
        if p == path or not os.path.exists(p):
            continue
        try:
            c2 = connect_ro(p)
            m = c2.execute("SELECT COUNT(*) FROM http_flows WHERE deleted_at IS NULL").fetchone()[0]
            c2.close()
            print("      %-70s http_flows=%d" % (p, m))
        except Exception as e2:
            print("      %-70s ERR %r" % (p, e2))
    print("    ⇒ 用 --db <路径> 指定；或确认本次是否本就不需要历史流量。")
    print()


def connect_ro(path):
    uri = "file:" + path.replace("\\", "/") + "?mode=ro"
    return sqlite3.connect(uri, uri=True, timeout=20)


def unescape(v):
    """http_flows 的 request/response 是 JSON 转义字符串，必须先反转义。"""
    if not isinstance(v, str):
        return v or ""
    t = v.lstrip()
    if t.startswith('"'):
        try:
            return json.loads(t)
        except Exception:
            pass
    return v


def split_resp(raw):
    for sep in ("\r\n\r\n", "\n\n"):
        i = raw.find(sep)
        if i >= 0:
            return raw[:i], raw[i + len(sep):]
    return raw, ""


def cmd_list(cur, args):
    cur.execute("""SELECT host, COUNT(*), MIN(created_at), MAX(created_at)
                   FROM http_flows WHERE deleted_at IS NULL GROUP BY host ORDER BY 2 DESC""")
    rows = cur.fetchall()
    cur.execute("SELECT COUNT(*) FROM http_flows WHERE deleted_at IS NULL")
    total = cur.fetchone()[0]
    print("总流量 %d 条，%d 个 host\n" % (total, len(rows)))
    print("%6s  %-46s  %s" % ("条数", "host", "时间范围"))
    for h, c, a, b in rows:
        flag = ""
        if args.target and h != args.target:
            flag = "  ← 非目标（噪声候选）"
        print("%6d  %-46s  %s ~ %s%s" % (c, h or "(空)", str(a)[:19], str(b)[:19], flag))
    print("\n提示：非目标 host 里可能混着「你自己的控制组请求」——那是刻意打的证据，"
          "别当噪声删掉，用 host 过滤即可。")


def cmd_host(cur, args):
    h = args.host
    cur.execute("""SELECT status_code, COUNT(*) FROM http_flows
                   WHERE deleted_at IS NULL AND host=? GROUP BY status_code ORDER BY 2 DESC""", (h,))
    print("=== %s 状态码分布 ===" % h)
    for sc, c in cur.fetchall():
        print("  %-6s %d" % (sc, c))
    cur.execute("""SELECT id, method, path, status_code, length(response)
                   FROM http_flows WHERE deleted_at IS NULL AND host=? ORDER BY id DESC LIMIT ?""",
                (h, args.limit))
    print("\n=== 最近 %d 条（id / 方法 / 路径 / 状态 / 响应长度）===" % args.limit)
    for i, m, p, sc, ln in cur.fetchall():
        print("  %5s %-7s %-64s %-4s %s" % (i, m, (p or "")[:64], sc, ln))
    print("\n注意：502 里很多是 Yakit 代理层自己产生的错误页，【不是目标响应】——"
          "判读前先看 Warning 头是 proxy timeout 还是 TLS 连接失败。")


def cmd_dump(cur, args):
    cur.execute("""SELECT id, url, method, request, response FROM http_flows WHERE id=?""", (args.dump,))
    row = cur.fetchone()
    if not row:
        sys.exit("找不到 id=%s" % args.dump)
    i, url, method, req, resp = row
    qh, qb = split_resp(unescape(req))
    sh, sb = split_resp(unescape(resp))
    print("=== id=%s  %s %s ===" % (i, method, url))
    print("--- 请求头 ---");   print(qh)
    print("--- 请求体 (%d B) ---" % len(qb));  print(qb[:4000])
    print("--- 响应头 ---");   print(sh)
    print("--- 响应体 (%d B) ---" % len(sb));  print(sb[:4000])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--host")
    ap.add_argument("--dump", type=int)
    ap.add_argument("--target", default="", help="--list 时用于标出噪声候选")
    ap.add_argument("--limit", type=int, default=30)
    ap.add_argument("--out", help="把报告写入该文件（UTF-8）。"
                                  "强烈建议使用：PowerShell 管道会用 GBK 解码子进程 stdout，"
                                  "导致中文乱码；直接落盘可绕开")
    ap.add_argument("--log", help="同 --out：控制台输出改写入该文件（本脚本结果即控制台输出）")
    args = ap.parse_args()

    if args.log or args.out:
        sys.stdout = open(args.log or args.out, "w", encoding="utf-8")

    db = pick_db(args.db)
    print("DB = %s\n" % db)
    con = connect_ro(db)
    warn_if_empty(con, db)
    cur = con.cursor()
    try:
        if args.dump:
            cmd_dump(cur, args)
        elif args.host:
            cmd_host(cur, args)
        else:
            cmd_list(cur, args)
    finally:
        con.close()


if __name__ == "__main__":
    main()
