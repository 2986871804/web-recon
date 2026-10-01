#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
check_consistency.py —— 文档间一致性静态检查（防"P3 族"漂移：跨文件引用失效、
词表多处定义、数字复制、形态映射缺项、命名三元组漂移……）

为什么要有它：delivery 与 phase2 曾对公开标识各说各话，两轮代理行为随机翻转——
"唯一权威"靠人肉维护必然复发。本脚本把一致性变成断言，折进 run_regression 闸门。

用法：python evals/check_consistency.py    # 全过 exit 0；任何红 exit 1
"""
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
DOCS = ["SKILL.md"] + sorted(
    "references/" + f for f in os.listdir(os.path.join(ROOT, "references")) if f.endswith(".md"))
ALL_FILES = DOCS + sorted(
    "scripts/" + f for f in os.listdir(os.path.join(ROOT, "scripts")) if f.endswith((".py", ".js")))

RESULTS = []


def check(name, ok, detail=""):
    RESULTS.append((name, ok, detail))
    print("  %s %s%s" % ("[PASS]" if ok else "[FAIL]", name,
                         ("  <- " + detail) if (detail and not ok) else ""))


def read(rel):
    return open(os.path.join(ROOT, rel), encoding="utf-8").read()


# 有意的跨仓库外部指针（文档已注明"从上游仓库获取"，非本技能内部文件）
EXTERNAL_OK = {"search-engine-syntax.md"}

FILE_HINT = {
    "delivery": "references/delivery.md",
    "phase1": "references/phase1-assets.md",
    "phase2": "references/phase2-fingerprint-js.md",
    "phase3": "references/phase3-api-verification.md",
    "environment": "references/environment-and-pitfalls.md",
}


def doc_text(rel):
    try:
        return read(rel)
    except OSError:
        return ""


def main():
    texts = {d: doc_text(d) for d in DOCS}
    skill = texts["SKILL.md"]

    # 1. 命名三元组：目录 = frontmatter name = evals skill_name
    m = re.search(r"^name:\s*(\S+)", skill, re.M)
    ev = json.load(open(os.path.join(ROOT, "evals", "evals.json"), encoding="utf-8"))
    triple = (os.path.basename(ROOT), m.group(1) if m else "?", ev.get("skill_name", "?"))
    check("命名三元组一致（目录=frontmatter=evals）", triple[0] == triple[1] == triple[2], str(triple))

    # 2. 文件引用可解析（*.md 与 scripts/*）
    bad = []
    for d in DOCS:
        for mm in re.finditer(r"\b([a-z0-9-]+\.md)\b", texts[d]):
            t = mm.group(1)
            if t in EXTERNAL_OK:
                continue
            if not (os.path.isfile(os.path.join(ROOT, t))
                    or os.path.isfile(os.path.join(ROOT, "references", t))):
                bad.append("%s -> %s" % (d, t))
        for mm in re.finditer(r"scripts/[a-z_]+\.(?:py|js)", texts[d]):
            if not os.path.isfile(os.path.join(ROOT, mm.group(0))):
                bad.append("%s -> %s" % (d, mm.group(0)))
    check("文件引用全部可解析", not bad, "; ".join(bad[:5]))

    # 3. 章节引用可解析（X.md §N / delivery §N / phaseN §N / SKILL 阶段 N）
    heads = {}
    for d in DOCS:
        heads[d] = set(re.findall(r"^#{2,3}\s+(?:§)?([0-9]+(?:\.[0-9]+)?)", texts[d], re.M))
        heads[d] |= set("阶段 " + n for n in re.findall(r"^### 阶段 ([0-9])", texts[d], re.M))
    bad = []
    for d in DOCS:
        for mm in re.finditer(r"(delivery|phase[1-3]|environment|[a-z0-9-]+\.md)[^\n]{0,10}§([0-9]+(?:\.[0-9]+)?)",
                              texts[d]):
            hint, sec = mm.group(1), "§" + mm.group(2)
            target = FILE_HINT.get(hint) or (
                hint if os.path.isfile(os.path.join(ROOT, hint)) else
                ("references/" + hint if os.path.isfile(os.path.join(ROOT, "references", hint)) else None))
            if target:
                key = mm.group(2)
                if key not in heads.get(target, set()):
                    bad.append("%s -> %s §%s（目标无此节）" % (d, target, key))
            else:                                   # "references §8" 这类无主提示：任一 phase 命中即过
                if not any(mm.group(2) in heads[p] for p in DOCS if p.startswith("references/phase")):
                    bad.append("%s -> references §%s（无任何 phase 文件含此节）" % (d, mm.group(2)))
        for mm in re.finditer(r"SKILL\.md 阶段 ([0-9])", texts[d]):
            if "阶段 " + mm.group(1) not in heads["SKILL.md"]:
                bad.append("%s -> SKILL.md 阶段 %s" % (d, mm.group(1)))
    check("章节引用全部可解析", not bad, "; ".join(bad[:6]))

    # 4. 词表枚举单一出处：四组权威枚举串只许出现在 delivery.md 且各一次
    enums = [
        "存活 / 不存活 / NXDOMAIN / 未探测",
        "未验证 / 待批准 / 已验证 / 未确认",
        "未鉴权可读 / 需凭据 / 不在此前缀",
        "OK / TRUNCATED / CL_MISSING / CHUNKED / FAILED",
    ]
    bad = []
    for e in enums:
        hits = [d for d in DOCS if e in texts[d]]
        if hits != ["references/delivery.md"]:
            bad.append("%r 出现于 %s（应为仅 delivery）" % (e[:30], hits))
    check("词表枚举仅定义于 delivery §0", not bad, "; ".join(bad[:4]))

    # 5. 预算数字单一出处：核心限速/预算数值只许出现在 SKILL.md（evals 断言的期望值除外）
    pats = [r"每批 ≤10", r"批间 ≥[13] 秒", r"单会话 ≤50", r"每主机总量 ≤50", r"总量 ≤100",
            r"每主机 ≤2 请求", r"上限 ≤4", r"并发 ≤5", r"并发 ≤2", r"重试（≤6 次）", r"重试 ≤3 次"]
    bad = []
    for d in DOCS:
        if d == "SKILL.md":
            continue
        for p in pats:
            if re.search(p, texts[d]):
                bad.append("%s 含 '%s'" % (d, p))
    check("预算数字仅存于 SKILL.md", not bad, "; ".join(bad[:6]))

    # 6. 陈旧措辞/隐私残留
    stales = [r"web-recon-master", r"五态", r"四类边界", r"双过滤", r"C:[/\\]Users"]
    bad = []
    for f in ALL_FILES:
        t = doc_text(f)
        for p in stales:
            if re.search(p, t):
                bad.append("%s 含 '%s'" % (f, p))
    check("陈旧措辞与硬编码用户路径零残留", not bad, "; ".join(bad[:6]))

    # 7. 形态→来源映射完备：提取器产出的每个形态都在 delivery 映射行里
    src = read("scripts/extract_endpoints.py")
    forms = set(re.findall(r'"形态": "([a-z-]+)', src))
    forms = {f.split(":")[0] for f in forms} - {"fetch 形态"}     # hidden:%s → hidden；字面误捕排除
    forms.discard("fetch 形态")
    mapping = next((ln for ln in texts["references/delivery.md"].splitlines()
                    if "形态 → 来源列映射" in ln), "")
    missing = sorted(f for f in forms if not re.search(r"[/` ,]%s[/` ,]" % re.escape(f), mapping))
    check("形态→来源映射覆盖提取器全部形态", not missing,
          "映射行缺：%s（提取器产出 %s）" % (missing, sorted(forms)))

    # 8. 嗅探前缀两脚本逐字一致
    sniffs = re.findall(r'startswith\(\(\"<!doctype html\", \"<html\"(?:, \"<head\")?\)\)',
                        read("scripts/extract_endpoints.py") + read("scripts/scan_comments.py"))
    uniq = set(sniffs)
    check("内容嗅探前缀两脚本一致（含 <head>）", len(uniq) == 1 and "<head" in next(iter(uniq)),
          str(uniq))

    # 9. mine_responses 的来源标记必须在 delivery 映射行里
    mine_src = read("scripts/mine_responses.py") if os.path.isfile(
        os.path.join(ROOT, "scripts", "mine_responses.py")) else ""
    if mine_src:
        check("mine_responses 来源标记在 delivery 映射中",
              "响应体提取" in texts["references/delivery.md"],
              "delivery.md 映射行缺「响应体提取」")

    # 10. API_PREFIX 单一出处：定义仅在 extract_endpoints，其余只 import
    defs = [f for f in ALL_FILES if f.startswith("scripts/")
            and re.search(r"API_PREFIX\s*=", read(f))
            and not f.endswith("extract_endpoints.py")]
    check("API_PREFIX 仅定义于 extract_endpoints", not defs, str(defs))

    bad = [r for r in RESULTS if not r[1]]
    print("\n一致性检查：%d/%d 通过%s" % (len(RESULTS) - len(bad), len(RESULTS),
                                       "" if not bad else "（失败 %d）" % len(bad)))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
