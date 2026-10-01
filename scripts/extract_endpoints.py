#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
extract_endpoints.py —— SPA 前端接口提取器的【参考实现】（技能自带，离线运行）

为什么要有它：解析规则写对了和写错了，准确率差 0.6 个百分点（lubo 678 条基准实测
96.36% → 99.70%）。规则写在文档里、每次重新实现会有方差 ⇒ 固化成脚本，消除方差。

本脚本实现技能里被基准测试验证过的全部规则：
  1. `url:` 任意位置匹配（非首键、键名复数 `methods:"get"` 都能命中）
       正则  (?<![A-Za-z_$])url\s*:
       方法  method[s]?\s*:\s*"([^"]*)"
  2. 🔴 路径重建【必须保留占位符】：
       "".concat("/a/", t, "/b")  →  /a/{t}/b        （不是 /a/b —— 那会把接口缝成伪路径）
       "/a/".concat(t)            →  /a/{t}
       `/a/${t}/b`                →  /a/{t}/b
     字面量原样保留，动态表达式一律变成 {占位符}，**绝不丢弃中间段**。
  3. 🔴 无前导斜杠的值（url:"face/batchImport"）→ 归一化补 "/"，**不许 startswith("/") 过滤掉**。
  4. --hidden：隐藏形态扫描（el-upload 的 action:、componentsUrl/uploadUrl/downUrl 等
     data 变量承载的地址），结果单独标 形态=hidden，供人工确认。

用法：
  python extract_endpoints.py --dir <文本目录> --out report.txt --csv out.csv
  # 目录递归扫 js/mjs/ts/jsx/vue/json/html/css/map（语言包里的接口不再被无声跳过）
  python extract_endpoints.py --files a.js b.js --csv out.csv
  python extract_endpoints.py --dir <js目录> --hidden --csv out.csv

退出码：0 = 正常；1 = 判定报告损坏（结果未经过滤）——链式调用据此机械检测降级
"""
import argparse, collections, csv, json, os, re, sys

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# ---------------------------------------------------------------- 基础正则
URL_KEY   = re.compile(r'(?<![A-Za-z_$])url\s*:')                       # 任意位置，非首键也命中
METHOD_RE = re.compile(r'method[s]?\s*:\s*"([^"]*)"')
STR_LIT   = re.compile(r'"((?:[^"\\]|\\.)*)"|\'((?:[^\'\\]|\\.)*)\'')

# 隐藏形态候选：任意以 Url/url/RL 结尾的标识符，或 el-upload 的 action。
# 🔴 不能只匹配「name: "字面量"」—— 上传/导出接口常写成
#    uploadDhFileUrl: "".concat(n["a"], "/dh/uploadDhFile")   ← 值是 concat 表达式
#    所以发现候选后要复用 url 的取值逻辑把整段表达式取出来，再分词重建。
HIDDEN_NAME = re.compile(r'\b([A-Za-z_$][\w$]*(?:[Uu]rl|RL)|action)\s*[:=]')

# 参数名提取：url 容器对象里的 params:{...} / data:{...} 键名（入清单「参数」列）
PARAMS_RE = re.compile(r'\bparams\s*:\s*\{([^{}]{0,300})\}')
DATA_RE   = re.compile(r'\bdata\s*:\s*\{([^{}]{0,300})\}')

def param_keys(obj):
    keys = []
    for rx in (PARAMS_RE, DATA_RE):
        m = rx.search(obj)
        if m:
            keys += re.findall(r'([A-Za-z_$][\w$]*)\s*:', m.group(1))
    seen, out = set(), []
    for k in keys:
        if k not in seen:
            seen.add(k); out.append(k)
    return ",".join(out[:12])

# 扫描的文本扩展名：JS 家族 + JSON 语言包/配置 + HTML + CSS + sourcemap。
# 只吃 .js 会无声丢掉语言包里的接口（实测：zh-CN.json 3 条接口被静默跳过）。
TEXT_EXTS = (".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".vue",
             ".json", ".html", ".htm", ".css", ".map")

# 通用 API 路径前缀（单一出处：extract_apis 粗筛 / scan_comments 旧接口扫描从此导入——
# 三处各自为政会漂移，且单目标残留词（frame/useraccount/account）不该进通用默认值）
API_PREFIX = r"(?:api|web|gateway|gw|cf|srv|service|rest|v[12])"

# HTML href 通道的真静态资产扩展名（页面路由 .html/.htm/.php/.jsp/.aspx 保留——
# 曾用"任意点号"启发式把 admin/dashboard.html 这类页面路由静默丢弃，eval 实测抓出）
HTML_ASSET_EXTS = {"css", "js", "mjs", "map", "png", "jpg", "jpeg", "gif", "webp", "svg",
                   "ico", "woff", "woff2", "ttf", "eot", "mp4", "webm", "mp3", "json", "xml", "pdf"}

# safe_fetch 判定文件（与其 --out 目录同处）：非 OK 的文件不得用于提取——
# 机械执行 delivery §0 的「TRUNCATED/CL_MISSING/FAILED 不提取；HTTP_4xx 只记存在被拦信号」。
# 否则 4xx 错误页里的 <a href>（支持链接/跳转目标）会以假阳性接口进清单。
FETCH_REPORT = "_fetch_report.json"


def find_fetch_reports(root):
    """递归发现 root 下所有层级的 _fetch_report.json（safe_fetch 的报告写在 --out 目录，常在 ./dl/ 子目录）。"""
    out = []
    for r, _, fs in os.walk(root):
        if FETCH_REPORT in fs:
            out.append(os.path.join(r, FETCH_REPORT))
    return out


def load_fetch_exclusions(report_paths):
    """解析判定报告 → ({(报告目录, 文件名): verdict}, [(报告路径, 失败原因)])。
    键按「报告所在目录 + 文件名」作用域——safe_fetch 的判定只对与其 --out 同目录的
    文件负责：多站点场景两个 dl/ 里各有 app.js 时，A 站的 TRUNCATED 不得吃掉
    B 站的 OK（按裸文件名做键会跨站误杀）。
    解析失败必须出声（返回错误表由调用方告警）——静默空表会让排除机制无声停摆，
    而"看起来在工作"比"没有"更危险。utf-8-sig 兼容带 BOM 的报告。"""
    ex, errs = {}, []
    for rp in report_paths:
        rd = os.path.abspath(os.path.dirname(rp))
        try:
            with open(rp, encoding="utf-8-sig") as f:
                data = json.load(f)
            for row in data:
                if isinstance(row, dict) and row.get("verdict") not in ("OK", "CHUNKED"):
                    ex[(rd, os.path.basename(str(row.get("file", ""))))] = row.get("verdict", "?")
        except Exception as e:
            errs.append((rp, "%s: %s" % (type(e).__name__, e)))
    return ex, errs


def hdr_verdict(path):
    """safe_fetch .hdr 侧车的判定重建（判定报告损坏时的降级复核）：
    新侧车（safe_fetch ≥ 本版）首行含 Status——可完整重建：
      Status≠200 → HTTP_<code>；200+CL 不符 → TRUNCATED；200+无CL → CL_MISSING；否则 OK。
    旧侧车（无 Status 行）退化为仅 CL 校验：不符 → TRUNCATED。
    无 .hdr / 读失败 → None（无法判定，不排除）。读取容 BOM（utf-8-sig，与判定报告同宽容度）。"""
    hp = path + ".hdr"
    if not os.path.isfile(hp):
        return None
    status, cl, te = None, None, ""
    try:
        for line in open(hp, encoding="utf-8-sig", errors="replace"):   # 容 BOM——与报告读取同宽容度
            k, _, v = line.partition(":")
            k = k.strip().lower()
            if k == "status" and status is None:
                m = re.match(r"\s*(\d{3})", v)
                if m:
                    status = int(m.group(1))
            elif k == "content-length" and cl is None:
                v = v.strip()
                if v.isdigit():
                    cl = int(v)
            elif k == "transfer-encoding" and not te:
                te = v.strip().lower()
    except Exception:
        return None
    if status is None:                      # 旧侧车：只能校完整性
        if cl is not None and os.path.getsize(path) != cl:
            return "TRUNCATED"
        return None
    if status != 200:
        return "HTTP_%d" % status
    if cl is None:
        return "CHUNKED" if "chunked" in te else "CL_MISSING"
    return "OK" if os.path.getsize(path) == cl else "TRUNCATED"


def hdr_bad(path):
    """降级模式下该文件是否应被排除（侧车重建判定为坏）。CHUNKED 可用于提取，不算坏。"""
    v = hdr_verdict(path)
    return v is not None and v not in ("OK", "CHUNKED")


# 主机常量定义（P2 前缀解析）：API_HOST = "https://x.com" / API_HOST: "..."
# 相对路径常量一并回填（API_HOST="/api/v2" 这类无 scheme 前缀——实测 eval 中代理被迫人工解析）
CONST_DEF_RE = re.compile(
    r'\b([A-Z][A-Z0-9_]{1,30})\s*[:=]\s*["\']((?:https?|wss?)://[^"\']{3,140}|/[a-zA-Z0-9_\-./]{2,60})["\']')


def build_consts(files):
    """全文件预扫描常量表 {NAME: url}，供 {API_HOST} 占位符回填基址。"""
    table = {}
    for f in files:
        try:
            text = open(f, encoding="utf-8", errors="replace").read()
        except Exception:
            continue
        for m in CONST_DEF_RE.finditer(text):
            table.setdefault(m.group(1), m.group(2))
    return table


def resolve_prefix(p, sus, consts):
    """前缀位置的 {大写常量} 占位符：常量表里有就回填基址并剥掉占位符；没有才标待人工。
    只处理前缀位置（占位符在路径中段时剥离会破坏路径）。"""
    pm = re.match(r"/?\{([A-Z][A-Z0-9_]{1,30})\}", p)   # 占位符带前导 /（normalize 补的）
    if not pm:
        return p, "", sus
    name = pm.group(1)
    if name in consts:
        np = p[pm.end():] or "/"
        return np, consts[name], (sus + "; " if sus else "") + "前缀已解析:%s=%s" % (name, consts[name])
    if re.search(r"API|HOST|CUR", name):
        return p, "", (sus + "; " if sus else "") + "前缀是配置常量，需解析租户配置模块确认归属"
    return p, "", sus

# ---------------------------------------------------------------- 工具函数

def _split_top(s):
    """按顶层逗号切参数（忽略字符串与括号内）。"""
    out, buf, depth, instr, i = [], "", 0, None, 0
    while i < len(s):
        c = s[i]
        if instr:
            buf += c
            if c == "\\":
                buf += s[i + 1] if i + 1 < len(s) else ""
                i += 2; continue
            if c == instr:
                instr = None
            i += 1; continue
        if c in "\"'`":
            instr = c; buf += c; i += 1; continue
        if c in "([{":
            depth += 1
        elif c in ")]}":
            if depth == 0:                       # 到 concat 的右括号
                break
            depth -= 1
        if c == "," and depth == 0:
            out.append(buf); buf = ""; i += 1; continue
        buf += c; i += 1
    if buf.strip():
        out.append(buf)
    return out


def _unescape(s):
    return s.replace("\\/", "/").replace("\\\\", "\\").replace('\\"', '"').replace("\\'", "'")


def base_of(p):
    """模板路径 → 基路径。🔴 必须把占位符替换成 '/' 再折叠斜杠，不能直接删 ——
    直接删会留下双斜杠（/a/{id}/b → /a//b），导致与「记基路径」的旧清单永远对不上。"""
    b = re.sub(r"/?\{[^}]*\}", "", p)
    b = re.sub(r"/{2,}", "/", b).rstrip("/")
    if b and not b.startswith("/"):
        b = "/" + b
    return b


def enclosing_obj(text, pos):
    """pos 处 url: 所在对象 { ... } 的 (start, end)。向前找最近未配对 '{'，向后找配对 '}'。"""
    depth, i, start = 0, pos, -1
    while i >= 0:
        c = text[i]
        if c == "}":
            depth += 1
        elif c == "{":
            if depth == 0:
                start = i; break
            depth -= 1
        i -= 1
    if start < 0:
        return None
    depth, j, instr = 0, start, None
    while j < len(text):
        c = text[j]
        if instr:
            if c == "\\":
                j += 2; continue
            if c == instr:
                instr = None
            j += 1; continue
        if c in "\"'`":
            instr = c
        elif c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return (start, j + 1)
        j += 1
    return None


def value_expr(obj_text, key_pos, sep_pos=None):
    """取键后值表达式（到顶层逗号或对象结尾）。
    sep_pos 显式给分隔符结束位置（= 赋值形态：HIDDEN_NAME 已吞下 [:=]，传 m.end()）；
    缺省从 key_pos 起找第一个冒号（url: 形态）。不传 sep_pos 时若 = 形态后文无冒号
    会静默漏掉、有冒号会借用无关键的值——本函数三种实测事故形态的根因记录：
    ① 只认冒号；② 借用他键的值；③ sep 模式无语句边界——顶层 = 赋值只停在顶层
    逗号/右括号，而 JS 语句边界是 ; 或换行，曾把后续整段语句缝进值里
    （"/upload/x";var y="/export/y" → 一条假路径）。sep 模式因此在深度 0 增加
    ; 与换行停点；冒号/concat 形态有 } / ) 天然边界，不加（多行拼接不回归）。"""
    stmt = sep_pos is not None
    if stmt:
        i = sep_pos
    else:
        i = obj_text.find(":", key_pos)
        if i < 0:
            return ""
        i += 1
    n = len(obj_text)
    while i < n and obj_text[i] in " \t\r\n":
        i += 1
    depth, instr, j = 0, None, i
    while j < n:
        c = obj_text[j]
        if instr:
            if c == "\\":
                j += 2; continue
            if c == instr:
                instr = None
            j += 1; continue
        if c in "\"'`":
            instr = c
        elif c in "([{":
            depth += 1
        elif c in ")]}":
            if depth == 0:
                break
            depth -= 1
        elif c == "," and depth == 0:
            break
        elif stmt and c in ";\n" and depth == 0:
            # ASI 续行：行尾是运算符/开括号则语句不可能终止（JS 自动分号插入同向规则），
            # 继续扫——多行拼接赋值（"/upload/" +\n "multi/line"）不丢第二段
            if not obj_text[i:j].rstrip().endswith(("+", "(", "[", "&", "|", "?")):
                break                                   # 语句边界：仅 sep 模式（= 赋值）
        j += 1
    return obj_text[i:j].strip()


# ---------------------------------------------------------------- 路径重建

def _tokenize_value(expr):
    """把 url 的值表达式切成 [('lit',str)/('dyn',str)] 序列。
    支持：字符串字面量、模板串 `${}`、`.concat(...)` 链、以及它们与标识符的混合。"""
    toks, buf, i, n = [], "", 0, len(expr)

    def flush():
        nonlocal buf
        s = buf.strip()
        if s:
            toks.append(("dyn", s))
        buf = ""

    while i < n:
        c = expr[i]
        if c in "\"'":
            j, lit = i + 1, ""
            while j < n:
                if expr[j] == "\\":
                    nxt = expr[j + 1] if j + 1 < n else ""
                    lit += {"n": "\n", "t": "\t"}.get(nxt, nxt)
                    j += 2; continue
                if expr[j] == c:
                    break
                lit += expr[j]; j += 1
            flush()
            toks.append(("lit", _unescape(lit)))
            i = j + 1
        elif c == "`":
            j, tmpl = i + 1, ""
            while j < n and expr[j] != "`":
                if expr[j] == "\\":
                    tmpl += expr[j:j + 2]; j += 2; continue
                tmpl += expr[j]; j += 1
            flush()
            for p in re.split(r"(\$\{[^}]*\})", tmpl):
                if p.startswith("${"):
                    toks.append(("dyn", p[2:-1].strip()))
                elif p:
                    toks.append(("lit", p))
            i = j + 1
        elif expr.startswith(".concat(", i):
            flush()
            j = i + 8
            depth = 0
            while j < n:
                ch = expr[j]
                if ch in "\"'`":
                    q = ch; j += 1
                    while j < n and expr[j] != q:
                        if expr[j] == "\\":
                            j += 1
                        j += 1
                elif ch == "(":
                    depth += 1
                elif ch == ")":
                    if depth == 0:
                        break
                    depth -= 1
                j += 1
            for a in _split_top(expr[i + 8:j]):
                a = a.strip()
                if not a:
                    continue
                m = re.fullmatch(r'"((?:[^"\\]|\\.)*)"|\'((?:[^\'\\]|\\.)*)\'', a)
                if m:
                    toks.append(("lit", _unescape(m.group(1) if m.group(1) is not None else m.group(2))))
                else:
                    toks.append(("dyn", a))
            i = j + 1
        else:
            buf += c; i += 1
    flush()
    return toks


def _ph(expr):
    """动态表达式 → 占位符名。清洗：去空白 → 去对象前缀 → 去一元 +/- → 非法字符回退 expr。"""
    s = re.sub(r"\s+", "", expr)
    s = re.sub(r"^[a-zA-Z_$][\w$]*\.", "", s)          # e.orgId → orgId
    s = s.strip("+-")                                   # 拼接运算符两侧都剥：API_HOST+"/x" 的 dyn token 是 "API_HOST+"，只剥前导会丢常量名
    if not s or len(s) > 24 or not re.fullmatch(r"[\w.\-$]*", s):
        return "expr"
    return s or "expr"


def rebuild_path(toks):
    """字面量原样保留、动态段变 {占位符}；返回 (路径, 是否含占位符)。
    纯拼接运算符（字面量之间只含 + 与空白的 dyn token）直接丢弃——合法 JS 里
    字面量间的裸 + 只有字符串拼接一种解释，确定性还原不产占位符；{expr} 的语义
    是"需填写的动态段"，把空拼接点标成占位符会让阶段 3 拿必 404 的假路径去探测。"""
    parts, has_ph = [], False
    for kind, v in toks:
        if kind == "lit":
            parts.append(v)
        elif re.fullmatch(r"[+\s]+", v):
            continue                # 纯拼接运算符：确定性连接；含标识符的 dyn 不受影响
        else:
            parts.append("{%s}" % _ph(v)); has_ph = True
    path = "".join(parts)
    return path, has_ph


def normalize(path):
    """归一化：无前导斜杠补 '/'（🔴 不许 startswith('/') 过滤）；返回 (路径, query, suspect)。"""
    query = ""
    if "?" in path:
        path, _, query = path.partition("?")
    suspect = ""
    if "//" in path:
        suspect = "含 //（已折叠，原样 %s）" % path
        path = re.sub(r"/{2,}", "/", path)   # 折叠后才能与"记基路径"的旧清单对上
    if path and not path.startswith("/"):
        path = "/" + path
    return path.rstrip("/"), query, suspect


# ---------------------------------------------------------------- 主提取

def extract_file(path, hidden=False, stats=None, consts=None):
    """返回 (records, url_total, obj_hit, err)。stats: Counter 记录剔除计数。"""
    if stats is None:
        stats = collections.Counter()
    consts = consts or {}
    try:
        text = open(path, encoding="utf-8", errors="replace").read()
    except Exception as e:
        return [], 0, 0, "READ_ERR %r" % e
    low = path.lower()
    # .map 是 JSON：源码在 sourcesContent[] 里且带 JSON 转义（url:\"/api/x\"）——直接扫原文
    # 会产出带转义尾巴的路径，与 minified JS 里同一端点的去重键不一致。先解析替换为源码原文。
    if low.endswith(".map"):
        try:
            _d = json.loads(text)
            _srcs = [s for s in (_d.get("sourcesContent") or []) if isinstance(s, str) and s]
            if _srcs:
                text = "\n/* ==== sourcesContent ==== */\n".join(_srcs)
        except Exception:
            pass    # 解析失败退回原文扫描（现状行为）
    # 内容嗅探（P3 防线）：.js 路径返回 HTML 错误页时按 HTML 形态处理，
    # 扩展名与内容形态脱钩不再导致整页静默漏
    head = text[:256].lstrip().lower()
    html_form = low.endswith((".html", ".htm")) or head.startswith(("<!doctype html", "<html", "<head"))
    recs = []
    url_total = len(URL_KEY.findall(text))
    hit = 0
    for m in URL_KEY.finditer(text):
        box = enclosing_obj(text, m.start())
        if not box:
            continue
        obj = text[box[0]:box[1]]
        expr = value_expr(obj, m.start() - box[0])
        if not expr:
            continue
        hit += 1
        toks = _tokenize_value(expr)
        raw, has_ph = rebuild_path(toks)
        p, q, sus = normalize(raw)
        if not p or p == "/":
            continue
        mm = METHOD_RE.search(obj)
        method = mm.group(1).strip().upper() if mm and mm.group(1).strip() else "?"
        rel = os.path.basename(path)
        # 绝对 URL 不是噪声：拆 基址+路径 落清单（phase2 §5 承诺"域外接口只记录，需另行授权"）；
        # 无路径的裸域（https://x.com/）仍走剔除计数。http 形态在此全权处理，
        # 故下方非接口过滤不再含 http 分支
        if raw.startswith(("http://", "https://")):
            mo = re.match(r"(https?://[^/\"']+)(/[^\"'?]*)", raw.split("?")[0])
            if mo and mo.group(2) and mo.group(2) != "/":   # 尾斜杠裸域：group(2)="/" 是真值，曾产出 接口路径='/' 的垃圾行
                stats["绝对URL"] += 1
                recs.append({"接口路径": mo.group(2), "基路径": mo.group(1),
                             "请求方式": method, "形态": "absolute",
                             "含占位符": "是" if has_ph else "否",
                             "query": ("?" + q) if q else "", "参数名": param_keys(obj),
                             "可疑": "绝对外链（域外基址），只记录不请求，需另行授权",
                             "来源文件": rel, "值表达式": expr[:160]})
            else:
                stats["非接口剔除"] += 1
            continue
        # 非接口过滤：告警文案 / 正则片段 / 打包器内部路径
        if (" " in raw or re.search(r"%[sd]", raw) or raw.startswith(("^", ":"))
                or "/node_modules/" in raw):
            stats["非接口剔除"] += 1
            continue
        # 纯动态路径（无任何静态前缀，如 /{e.id}）→ 拿不出可用的接口，单独计数
        if re.fullmatch(r"/\{[^}]*\}", p):
            stats["纯动态路径"] += 1
            continue
        p, bres, sus = resolve_prefix(p, sus, consts)
        stats["url形态"] += 1
        recs.append({"接口路径": p, "基路径": bres or base_of(p),
                     "请求方式": method, "形态": "url",
                     "含占位符": "是" if has_ph else "否",
                     "query": ("?" + q) if q else "",
                     "参数名": param_keys(obj),
                     "可疑": sus, "来源文件": rel, "值表达式": expr[:160]})
    if hidden:
        for m in HIDDEN_NAME.finditer(text):
            name = m.group(1)
            expr = value_expr(text, m.start(), m.end())   # 传分隔符位：= 赋值形态从 = 后取值，不再借用他键
            if not expr:
                continue
            # 不再要求值必须以引号/concat 开头 —— action:e.AI_API_HOST+"/dh/uploadDhFile"
            # 这类「常量 + 字面量」表达式同样要收；能不能当接口交给后面的结果过滤器判断
            toks = _tokenize_value(expr)
            raw, has_ph = rebuild_path(toks)
            p, q, sus = normalize(raw)
            # 噪声过滤：无斜杠 / 含空格 / 含 CJK 或全角符号 / 太短 —— i18n 文案与告警文案都在这里挡掉
            if not p or len(p) < 4 or "/" not in p \
                    or re.search(r"\s|[\u4e00-\u9fff\u3000-\u303f\uff00-\uffef]", p):
                stats["hidden噪声"] += 1
                continue
            if p.startswith(("http://", "https://")):
                sus = (sus + "; " if sus else "") + "绝对外链"
            p, bres, sus = resolve_prefix(p, sus, consts)
            stats["hidden形态"] += 1
            recs.append({"接口路径": p, "基路径": bres or base_of(p),
                         "请求方式": "?", "形态": "hidden:%s" % name,
                         "含占位符": "是" if has_ph else "否",
                         "query": ("?" + q) if q else "",
                         "可疑": sus or "hidden 形态，需人工确认是否接口",
                         "来源文件": os.path.basename(path), "值表达式": expr[:160]})
    # ---- ③ 补充扫：字符串字面量紧跟 .concat(...) 的链 ----
    # 覆盖「下载/导出函数首参是 URL」的形态：Object(m["a"])("".concat(c["a"],"/assistant/exportSessionList"),…)
    # 这种写法没有 url: 键、也没有 xxxUrl: 赋值，前面两遍都看不见。
    seen_expr = set()
    for m in re.finditer(r'"((?:[^"\\]|\\.)*)"\s*\.\s*concat\(', text):
        start = m.start()
        j, depth, instr = m.end() - 1, 0, None
        while j < len(text):
            c = text[j]
            if instr:
                if c == "\\":
                    j += 2; continue
                if c == instr:
                    instr = None
                j += 1; continue
            if c in "\"'`":
                instr = c
            elif c == "(":
                depth += 1
            elif c == ")":
                depth -= 1
                if depth == 0:
                    break
            j += 1
        expr = text[start:j + 1]
        if expr in seen_expr:
            continue
        seen_expr.add(expr)
        toks = _tokenize_value(expr)
        raw, has_ph = rebuild_path(toks)
        p, q, sus = normalize(raw)
        # 结果过滤：要像接口 —— 以 / 开头、有字母、无空格、无 CJK、不是纯占位符
        if not p or len(p) < 5 or not p.startswith("/"):
            continue
        if not re.search(r"[A-Za-z]", p) or re.search(r"\s|[\u4e00-\u9fff\u3000-\u303f\uff00-\uffef]", p):
            stats["concat噪声"] += 1
            continue
        stats["concat形态"] += 1
        recs.append({"接口路径": p, "基路径": base_of(p),
                     "请求方式": "?", "形态": "concat",
                     "含占位符": "是" if has_ph else "否",
                     "query": ("?" + q) if q else "",
                     "可疑": (sus + "; " if sus else "") + "concat 链，需确认是否接口",
                     "来源文件": os.path.basename(path), "值表达式": expr[:160]})

    # JSON 语言包/前端配置：值里的接口路径（键不叫 url —— i18n 高频藏接口名与权限词）
    if path.lower().endswith(".json"):
        for m in re.finditer(r'"(/?' + API_PREFIX + r'/[a-zA-Z0-9_\-/]{2,150})"', text):
            p = m.group(1) if m.group(1).startswith("/") else "/" + m.group(1)
            if p == "/" or re.search(r"\s", p):
                continue
            stats["json形态"] += 1
            recs.append({"接口路径": p, "基路径": base_of(p),
                         "请求方式": "?", "形态": "json",
                         "含占位符": "否", "query": "",
                         "可疑": "来自 JSON 值，需上下文确认", "来源文件": os.path.basename(path),
                         "值表达式": m.group(1)[:160]})

    # CSS：url()/@import 引用（跳过 data URI、外链、带扩展名的静态资源）
    if path.lower().endswith((".css", ".map")):
        for m in re.finditer(r'(?:url|import)\s*\(?\s*[\'"]?([^\'")\s]{2,200})[\'"]?', text):
            u = m.group(1)
            if u.startswith(("data:", "http", "//", "#")) or "." in u.rsplit("/", 1)[-1]:
                continue
            stats["css形态"] += 1
            recs.append({"接口路径": u if u.startswith("/") else "/" + u,
                         "基路径": "", "请求方式": "?", "形态": "css",
                         "含占位符": "否", "query": "",
                         "可疑": "CSS 引用，需确认是资产还是接口", "来源文件": os.path.basename(path),
                         "值表达式": u[:160]})

    # HTML：href/src/action 属性——引号与无引号形态都收（HTML5 无引号合法，整页无引号时
    # 带引号正则会 0 命中）；前导斜杠与相对路径都收，复用 normalize 归一化。
    # 门控用内容嗅探（html_form）：.js 存成 HTML 错误页时也能走本分支
    if html_form:
        for m in re.finditer(r'\b(?:href|src|action|data-url)\s*=\s*[\'"]?([^\'"\s>]{2,200})[\'"]?', text):
            raw = m.group(1).split("#")[0]
            if (not raw or raw.startswith(("data:", "http", "//", "javascript:",
                                           "mailto:", "tel:", "{", "<")) or " " in raw):
                continue
            seg = raw.rsplit("/", 1)[-1]
            if "." in seg and seg.rsplit(".", 1)[-1].lower() in HTML_ASSET_EXTS:
                continue              # 真静态资产（css/js/图片/字体…）；页面路由 .html/.php 等保留
            p, q, _ = normalize(raw)
            if not p or p == "/" or len(p) < 3:
                continue
            page_route = seg.lower().endswith((".html", ".htm"))
            stats["html形态"] += 1
            recs.append({"接口路径": p, "基路径": base_of(p),
                         "请求方式": "?", "形态": "html",
                         "含占位符": "否",
                         "query": ("?" + q) if q else "",
                         "可疑": "页面路由（站点导航面，非接口）" if page_route
                                 else "HTML 链接，需区分页面路由与接口",
                         "来源文件": os.path.basename(path),
                         "值表达式": raw[:160]})

    # 裸 fetch("/api/...") 首参字面量——axios/this.http 之外最常见的调用形态（.vue 高发），
    # eval 实测精提 0 命中、仅靠粗筛+人工补录兜底；只收字面量首参，动态首参不猜
    for m in re.finditer(r'\bfetch\s*\(\s*(["\'])(/[^"\']{2,200})\1', text):
        p, q, _ = normalize(m.group(2))
        if p and p != "/":
            stats["fetch形态"] += 1
            recs.append({"接口路径": p, "基路径": base_of(p),
                         "请求方式": "?", "形态": "fetch",
                         "含占位符": "否",
                         "query": ("?" + q) if q else "", "参数名": "",
                         "可疑": "裸 fetch 首参字面量", "来源文件": os.path.basename(path),
                         "值表达式": m.group(2)[:160]})

    # WebSocket / SSE / GraphQL 操作名（产出承诺必须有提取通道）
    for m in re.finditer(r'new\s+WebSocket\s*\(([^)]{2,200})\)', text):
        toks = _tokenize_value(m.group(1))
        raw, has_ph = rebuild_path(toks)
        p, q, _ = normalize(raw)
        p, bres, _sus = resolve_prefix(p, "", consts)
        if p and p != "/":
            stats["ws形态"] += 1
            recs.append({"接口路径": p, "基路径": bres, "请求方式": "WSS", "形态": "ws",
                         "含占位符": "是" if has_ph else "否",
                         "query": ("?" + q) if q else "", "参数名": "",
                         "可疑": "WebSocket 端点，未验证", "来源文件": os.path.basename(path),
                         "值表达式": m.group(1)[:160]})
    for m in re.finditer(r'new\s+EventSource\s*\(([^)]{2,200})\)', text):
        toks = _tokenize_value(m.group(1))
        raw, has_ph = rebuild_path(toks)
        p, q, _ = normalize(raw)
        p, bres, _sus = resolve_prefix(p, "", consts)
        if p and p != "/":
            stats["sse形态"] += 1
            recs.append({"接口路径": p, "基路径": bres, "请求方式": "SSE", "形态": "sse",
                         "含占位符": "是" if has_ph else "否",
                         "query": ("?" + q) if q else "", "参数名": "",
                         "可疑": "SSE 端点，未验证", "来源文件": os.path.basename(path),
                         "值表达式": m.group(1)[:160]})
    for m in re.finditer(r'["\'](wss?://[^"\']{3,180})["\']', text):
        stats["ws形态"] += 1
        recs.append({"接口路径": m.group(1), "基路径": "", "请求方式": "WSS", "形态": "wss-url",
                     "含占位符": "否", "query": "", "参数名": "",
                     "可疑": "wss 绝对地址，未验证", "来源文件": os.path.basename(path),
                     "值表达式": m.group(1)[:160]})
    for m in re.finditer(r'operationName\s*[:=]\s*["\']([^"\']{2,80})["\']', text):
        stats["graphql形态"] += 1
        recs.append({"接口路径": m.group(1), "基路径": "", "请求方式": "?", "形态": "graphql-op",
                     "含占位符": "否", "query": "", "参数名": "",
                     "可疑": "GraphQL operationName，配合 /graphql 端点使用", "来源文件": os.path.basename(path),
                     "值表达式": m.group(1)[:160]})

    return recs, url_total, hit, ""


def main():
    ap = argparse.ArgumentParser(description="SPA 前端接口提取（参考实现，离线）")
    ap.add_argument("--dir", help="文本目录（递归扫 js/json/html/css/ts/vue/map）")
    ap.add_argument("--files", nargs="*", help="显式指定 JS 文件")
    ap.add_argument("--hidden", action="store_true", help="同时扫隐藏形态（action:/componentsUrl/...）")
    ap.add_argument("--csv", help="输出 CSV（UTF-8 BOM，Excel 可直接开）")
    ap.add_argument("--site", default="-",
                    help="站点归属打标（subdomains.csv 的存活子域名；多站点按站点目录分次运行各传各的，"
                         "缺省 '-'。归属在生成时打上，不事后补填——多站点几百行手工补必错）")
    ap.add_argument("--out", help="输出文本报告（UTF-8）——避免 PowerShell 管道 GBK 乱码")
    ap.add_argument("--log", help="控制台输出改写入该文件（UTF-8），不再打印")
    args = ap.parse_args()

    files, skipped_ext, missing_files = [], 0, []
    report_paths = []
    if args.files:
        missing_files = [f for f in args.files if not os.path.exists(f)]
        files += [f for f in args.files if os.path.exists(f)]
    if args.dir:
        report_paths += find_fetch_reports(args.dir)         # 任意层级（常在 ./dl/ 子目录）
        for root, _, fs in os.walk(args.dir):
            for f in fs:
                if f.lower().endswith(TEXT_EXTS):
                    files.append(os.path.join(root, f))
                elif not f.lower().endswith(".hdr"):         # .hdr 是自己的落盘头文件，不计
                    skipped_ext += 1
    if args.files:
        for d in {os.path.dirname(os.path.abspath(f)) for f in files}:
            rp = os.path.join(d, FETCH_REPORT)
            if os.path.isfile(rp) and rp not in report_paths:
                report_paths.append(rp)
    if not files:
        ap.error("请用 --dir 或 --files 提供至少一个文本文件")
    # 统一过滤：--files 与 --dir 走同一条路径，不依赖填充时序
    excl, report_errors = load_fetch_exclusions(report_paths)
    dl_excluded = collections.Counter()
    kept = []
    for f in files:
        b = os.path.basename(f)
        key = (os.path.dirname(os.path.abspath(f)), b)
        if b == FETCH_REPORT:                                # 判定文件自身不进提取
            dl_excluded["REPORT"] += 1
        elif key in excl:                                    # 非 OK 判定：仅对与报告同目录的文件生效
            dl_excluded[excl[key]] += 1
        elif report_errors and hdr_bad(f):                   # 降级回退：侧车重建判定（Status+CL）
            dl_excluded["%s(hdr回退)" % hdr_verdict(f)] += 1
        else:
            kept.append(f)
    files = kept

    consts = build_consts(files)

    all_recs, per_file, tot_url, tot_hit = [], [], 0, 0
    stats = collections.Counter()
    for f in sorted(set(files)):
        recs, u, h, err = extract_file(f, hidden=args.hidden, stats=stats, consts=consts)
        tot_url += u; tot_hit += h
        if err:
            per_file.append((os.path.basename(f), 0, err))
            continue
        all_recs += recs
        per_file.append((os.path.basename(f), len(recs), ""))

    # 去重（路径+方法），保留出现次数与来源文件集合
    dedup = collections.OrderedDict()
    for r in all_recs:
        # 去重键含基路径——与 delivery §1 的合并契约（完整 URL = 基址+路径, 方法）一致；
        # 只按 (路径,方法) 会把不同绝对基址的同名路径互相吞掉（多租户/多区域静默丢失）
        k = (r["接口路径"], r["基路径"], r["请求方式"])
        if k not in dedup:
            d = dict(r); d["出现次数"] = 0; d["来源文件集"] = set()
            dedup[k] = d
        dedup[k]["出现次数"] += 1
        dedup[k]["来源文件集"].add(r["来源文件"])
    # 反查索引的原始数据（须在下面把 来源文件集 截断/计数化之前取）。
    # 聚合不能用字典推导——同路径多基址/多方法是多条 dedup 记录，推导后者覆盖前者，
    # 反查索引丢来源文件（曾实测 /api/dup ← 只剩 b.js）；setdefault.update 才是并集
    by_path = {}
    for k, d in dedup.items():
        by_path.setdefault(k[0], set()).update(d["来源文件集"])
    for d in dedup.values():
        d["来源文件"] = ",".join(sorted(d["来源文件集"])[:4]) + ("…" if len(d["来源文件集"]) > 4 else "")
        d["来源文件集"] = len(d["来源文件集"])

    L = []
    L.append("=== 提取汇总 ===")
    L.append("扫描文本文件 %d 个（跳过非文本 %d 个）｜`url:` 出现 %d 次｜成功入对象 %d 次｜去重后接口 %d 条（其中含占位符 %d 条、hidden 形态 %d 条）"
             % (len(set(files)), skipped_ext, tot_url, tot_hit, len(dedup),
                sum(1 for d in dedup.values() if d["含占位符"] == "是"),
                sum(1 for d in dedup.values() if d["形态"].startswith("hidden"))))
    if args.site == "-":
        L.append("⚠ 未传 --site：站点列全部为 '-'（多站点场景须可回答归属，规则见 delivery §1.5）")
    if missing_files:
        # 无静默丢弃：--files 里不存在的文件出声进报告
        L.append("⚠ --files 中 %d 个文件不存在，已跳过：%s"
                 % (len(missing_files), ",".join(missing_files[:5]) + ("…" if len(missing_files) > 5 else "")))
    if report_errors:
        hdr_n = sum(n for k, n in dl_excluded.items() if k.endswith("(hdr回退)"))
        L.append("⚠ 判定报告读取失败 %d 份——排除机制未生效；已用 .hdr 侧车重建判定排除 %d 个"
                 "（Status+Content-Length，覆盖 TRUNCATED 与 4xx；旧侧车无 Status 行仅能校截断），"
                 "无 .hdr 的文件无法复核、已进入提取：%s"
                 % (len(report_errors), hdr_n,
                    "; ".join("%s(%s)" % (p, r) for p, r in report_errors[:3])
                    + ("…" if len(report_errors) > 3 else "")))
    if dl_excluded:
        L.append("因下载判定排除 %d 个：%s —— 非 OK 文件不得用于提取（4xx 错误页的 href 是"
                 "支持链接/跳转目标，不进清单，只记存在被拦信号）"
                 % (sum(dl_excluded.values()),
                    ", ".join("%s×%d" % kv for kv in sorted(dl_excluded.items()))))
    L.append("")
    L.append("🔎 解析覆盖基线自查：`url:` 总数 %d vs 入对象 %d —— 两者差额 = %d"
             "（差额大说明有 `url:` 没能配到所属对象，需人工看）" % (tot_url, tot_hit, tot_url - tot_hit))
    L.append("")
    # 通道健康直方图（零也在场）：某通道整库为 0 本身是信号——前端形态变迁时最先在这里显形
    # （裸 fetch 盲区就是 eval 抓出来的：修复前该直方图里 fetch 恒 0 而无人看见）
    chans = [("url", "url形态"), ("hidden", "hidden形态"), ("concat", "concat形态"),
             ("json", "json形态"), ("css", "css形态"), ("html", "html形态"),
             ("fetch", "fetch形态"), ("ws/wss", "ws形态"), ("sse", "sse形态"),
             ("graphql", "graphql形态"), ("absolute", "绝对URL")]
    L.append("通道命中直方图（零也是信号，勿略过）：" +
             " · ".join("%s %d" % (n, stats.get(k, 0)) for n, k in chans))
    L.append("")
    L.append("🧹 剔除统计：非接口 %d 条（告警文案/正则片段/绝对外链/打包器路径）、"
             "纯动态路径 %d 条（只有 {占位符} 没有静态前缀，拿不出可用接口）"
             % (stats["非接口剔除"], stats["纯动态路径"]))
    L.append("")
    if args.csv:
        with open(args.csv, "w", encoding="utf-8-sig", newline="") as f:
            w = csv.DictWriter(f, fieldnames=[
                "接口路径", "基路径", "请求方式", "形态", "含占位符", "query", "参数名", "可疑",
                "出现次数", "来源文件", "站点", "值表达式"], extrasaction="ignore")
            w.writeheader()
            for d in dedup.values():
                d["来源文件集"] = str(d["来源文件集"])
                d["站点"] = args.site
                w.writerow(d)
        L.append("CSV 已写：%s（%d 行）" % (args.csv, len(dedup)))
    L.append("")
    L.append("=== 每文件命中数 ===")
    for name, n, err in per_file:
        if n or err:
            L.append("  %-56s %5d  %s" % (name[:56], n, err))
    zeros = [name for name, n, err in per_file if not n and not err]
    if zeros:
        L.append("  ⚠ 0 命中文件 %d 个（可见性计数——整批 0 命中时先怀疑解析面，别当没有接口）：%s"
                 % (len(zeros), ",".join(zeros[:10]) + ("…" if len(zeros) > 10 else "")))
    L.append("")
    L.append("=== 反查索引（接口 → 全部来源文件，完整不截断）===")
    for pth in sorted(by_path):
        L.append("  %s ← %s" % (pth, ",".join(sorted(by_path[pth]))))

    out_text = "\n".join(L)
    if args.out:
        open(args.out, "w", encoding="utf-8").write(out_text)
    if args.log:
        open(args.log, "w", encoding="utf-8").write(out_text + "\n")
    else:
        print(out_text)
    # 退出码（对齐 safe_fetch 约定：0=正常，1=需注意）：判定报告损坏 = 结果未经过滤，机器可检测
    return 1 if report_errors else 0


if __name__ == "__main__":
    sys.exit(main())
