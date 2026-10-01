# web-recon

授权范围内 Web 攻击面的**只读测绘**技能——子域名枚举、指纹识别、前端 JS/SPA 打包产物挖掘、接口清单整理与导出、接口存在性与鉴权验证、敏感文件泄露排查、apk/ipa 移动端包静态解包分析。

> 仅限授权测试。全程只发 GET / HEAD / OPTIONS，不做漏洞利用。

## 为什么需要它

测绘的本质是**扩大攻击面**：多发现、持续发现。本技能把这件事工程化——每条规则有出处、每个机制有断言、每处承诺有实现。

## 三阶段模型

| 阶段 | 观测对象 | 产出 |
|---|---|---|
| **1 资产发现** | 公开渠道记录（证书透明/DNS/归档/测绘引擎） | `subdomains.csv` |
| **2 内容测绘** | 页面与静态资源 | 指纹表、`入口清单.csv`、泄露点清单 |
| **3 API 验证** | 接口响应包络（存在性/鉴权） | 状态与验证结果列更新 |

各阶段速率参数不同（越接近业务路径越紧），产出通过**数据流**对接：阶段 1 建 → 阶段 2 填充 → 阶段 3 验证 → 交付时导出报告与未闭环清单。

## 硬性规则（全程遵守，任何阶段不豁免）

1. **不删改目标数据**：只发 GET / HEAD / OPTIONS
2. **只测授权范围**：范围外域名只记录不请求
3. **只加不减**：未验证/未确认/NXDOMAIN/阴性都是记录状态，不是丢弃理由
4. **结论标来源**：真实请求/落盘文件/推断，数量来自工具输出

限速为续航：被封 = 进度归零。

## 快速开始

```bash
git clone https://github.com/<user>/web-recon.git
cd web-recon

# 自检（离线零目标请求，81 项断言 + 9 项文档一致性检查）
python evals/run_regression.py
```

### 下载 JS（带完整性校验）

```bash
python scripts/safe_fetch.py --base https://<target> --urls urls.txt --out ./dl --retry 6
```

### 提取接口（粗筛→精提→对账）

```bash
python scripts/extract_apis.py <js目录>                          # 粗筛：分级+调用点分类
python scripts/extract_endpoints.py --dir <js目录> --hidden --csv out.csv   # 精提
python scripts/extract_apis.py <js目录> --reconcile-fine out.csv # 对账：粗筛有/精提无（盲区候选）
```

### 注释敏感线索扫描

```bash
python scripts/scan_comments.py --dir <js目录> --site <子域名> --csv clues.csv
```

### 浏览器运行时钩子

将 `scripts/hook_inject.js` 粘贴到控制台 → 操作页面 → 收割 `window.__cap`。

## 自带防线

| 层 | 工具 | 拦什么 |
|---|---|---|
| 行为回归 | `run_regression.py`（81 项，A–E 组） | 代码退化、静默失效、盲区回归 |
| 文档一致性 | `check_consistency.py`（9 项，折在回归末尾） | 引用失效、词表多处定义、数字复制、映射缺项 |
| 提示词评测 | `evals/evals.json`（4 用例 35 断言） | 未知盲区 + 代理行为纪律 |

## 文件结构

```
web-recon/
├── SKILL.md                    # 立法层：硬性规则 + 阶段规则 + 数据流（84 行）
├── references/                 # 实现细节层（5 篇）
│   ├── phase1-assets.md        # 资产发现：被动源/主动验证/接管嫌疑/排序
│   ├── phase2-fingerprint-js.md# 内容测绘：指纹/下载/双路线提取/盲区可见性/移动端
│   ├── phase3-api-verification.md # API 验证：判定表/一发流/红线
│   ├── environment-and-pitfalls.md # 排错：十一假象表/代理/Windows
│   └── delivery.md             # 交付：状态词表/入口清单列/schema/交接协议
├── scripts/                    # 可执行层（6 脚本，仅标准库）
└── evals/                      # 质量闸门
    ├── run_regression.py       # 81 项行为回归（A 侧车/B 判定/C 提取/D 注释/E 生产者）
    ├── check_consistency.py    # 9 项文档一致性静态检查
    └── evals.json              # 4 用例提示词级评测
```

## 交付物

| 文件 | 内容 |
|---|---|
| `subdomains.csv` | 子域、IP、CNAME、状态（存活/不存活/NXDOMAIN/未探测） |
| `入口清单.csv` | URL、方法、参数、来源、站点、状态、验证结果 |
| `测绘报告.md` | 授权边界、指纹表、接口清单（实测率+站点覆盖率）、泄露点、未闭环清单 |
| `leaks.csv` | 级别、类别、内容（按长度打码）、上下文、来源文件、站点 |
| `clues.csv` | 注释线索：中文/英文凭据、内网裸地址、注释旧接口（独立通道，核验后才升级） |

## License

MIT
