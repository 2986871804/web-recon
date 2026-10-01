<!-- 阶段 1 实现细节：域名与子域名发现。状态词以 delivery.md §0 为准；阶段规则见 SKILL.md。 -->

# 阶段 1：资产发现

## §0 企业锚定与范围扩展

输入可以是域名也可以是公司名——公司名先走锚定链再进子域名枚举。

### 锚定链（公司名 → 主域）

```
公司名
  → 企业信息平台查 websiteList + 邮箱域名（双证交叉）
  → ICP 备案核验（第三方平台查询，不触达目标）
  → 主域清单
```

- 同主体多备案**全收**（一个公司可能备案多个域名，全是合法测试范围）
- websiteList 与邮箱域名不一致时以 ICP 备案为准，websiteList 做旁证
- 锚定证据（公司名、统一社会信用代码、备案号、websiteList、邮箱域名）进报告 §0 授权边界表

### 股权穿透扩展（默认关闭，须用户明确开启）

| 操作 | 阈值 | 进范围？ |
|---|---|---|
| 控股 ≥51% | 有控股权证据 | ✅ 进范围（须用户逐次确认） |
| 实际控制 | 实控人证据链（法院/工商/年报披露） | ✅ 进范围（须用户逐次确认） |
| 参股 <51% | 无控股权 | ❌ 只记录不测 |
| 二级穿透（孙公司） | — | ❌ 先记录不展开（范围膨胀节制） |
| 历史已退出 | 已转让/注销 | ❌ 不进范围（但历史资产面可留意记录） |

每个扩展实体须落**证据链**进 §0 授权边界表：持股比例 + 统一社会信用代码 + ICP 备案号。证据不齐的只记录不进范围。

**扩权决策永远留在用户手里**——技能提供归属证据，用户逐次确认后实体才进入测试范围。与阶段 3 写入测试"须逐次批准"同一个模式。

### IP 归属

对发现的 IP：注册归属（whois）/ ICP 绑定 / 反查（同 C 段其他域名）三源交叉验证，证据进 §0。归属不明的 IP 标"待确认"（不是"不属于目标"）。

## 顺序：被动 → 主动

先用被动源（不向目标发包），拿到子域名清单后再做主动验证。被动结果为空 ≠ 无资产——各源都有收录时滞，空结果要换源再试。

## 被动源

| 源 | 方法 | 特点 |
|---|---|---|
| 证书透明日志 | `https://crt.sh/?q=%.<域名>&output=json` 解析 name_value 去重；再补一发 `%25.%25.<域名>` 抓二级深度 SAN（单层通配会漏） | 一次拿全量历史子域；`*.` 条目展开时去掉 `*.` |
| CT 降级链 | crt.sh 502 时不重试循环，按序换源：Censys certificates（`names:<域名>`）→ CertSpotter（`/v1/issuances?include_subdomains=true&expand=dns_names`）→ OTX passive_dns → urlscan（`domain:<域名>`） | crt.sh 高峰期常 502，降级比硬等快 |
| 历史归档 | Wayback CDX：`web.archive.org/cdx/search/cdx?url=<域名>/*&fl=original,timestamp,statuscode,mimetype&collapse=urlkey`；`filter=mimetype:application/javascript` 定向取历史 JS | 已下线页面与旧版 JS——旧 JS 里有前端已移除但后端未下线的接口；`filter=original:.*\.js\.map$` 挖历史 sourcemap；**归档响应体回捞见 phase2-fingerprint-js.md §2.5** |
| 聚合取 URL | gau（Wayback + CommonCrawl + OTX + URLScan 四源合一），`--blacklist png,jpg,css` 滤静态 | 比单用 Wayback 多三源 |
| 被动 DNS / 情报站 | SecurityTrails、urlscan | urlscan 带截图与技术栈识别 |
| Chaos API | `https://dns.projectdiscovery.io/dns/<域名>/subdomains`（免费 key） | projectdiscovery 维护的子域库 |
| 搜索引擎 | `site:<域名> -www`，扩展 `inurl:` / `filetype:` / `intitle:"index of"` | 覆盖有限，零成本 |
| 聚合工具 | subfinder / amass passive（已配 key 时；key 收益排序 SecurityTrails > Shodan > VirusTotal > Censys） | 无 key 时结果显著缩水 |

### 测绘引擎（补 DNS 枚举盲区的主源）

DNS 枚举拿不到的三类资产只有测绘引擎能给：**非标端口 Web**（`dev.x.com:8443`）、**DNS 记录已删但服务在线的"幽灵"子域**、**IP 反查同服务器的其他域名**。查询不触达目标，免费额度：Quake/Hunter > FOFA。

| 引擎 | 查询语法（示例） | 特长 |
|---|---|---|
| FOFA | `domain="<域名>"`、`cert="<域名>"`、`icon_hash="<哈希>"`、`title="登录"` | 国内资产量、favicon 搜索 |
| Quake | `domain:"<域名>" AND port:8443`、`response:"admin"`、`cert:""` | 指纹识别、IP 段/AS 关联 |
| Hunter | `web.title=""`、`app.name=""`、`cert.subject=""` | C 段聚合、域名关联 |
| Shodan | `hostname:<域名>`、`ssl.cert.subject.cn:*.target.com`、`org:"<组织名>"`、`net:<CIDR>`、`asn:AS<号>` | 面向 IP/端口/证书维度 |
| Censys | `names:<域名>`、`autonomous_system.name:"<组织>"` | 证书库全 |

- **单引擎独有资产的判据**：多引擎交叉后仅一家收录的条目标注"可能新上线或已下线"，入清单但须二次验证——各引擎收录时滞不同。
- **零发包端口观察**（端口扫描的被动替代）：Shodan InternetDB 免费 API（`https://internetdb.shodan.io/<IP>`，限 1 请求/秒）拿开放端口与已知 CVE 标签，不向目标发包。
- 语法手册（FOFA/Quake/Hunter 全量）：GitHub `wgpsec/AboutSecurity` 仓库内 `skills/recon/passive-recon/references/search-engine-syntax.md`（合集环境可在 pentest-skills-github 下找到；本技能安装为独立目录后**不含**此文件，从仓库获取）。引擎语法最后核验 2026-09，核验源=各引擎官方语法文档页对照。
- favicon 哈希是比 IP/域名更稳定的组织指纹：一站点 favicon hash 可反查同组织其他资产。

## 主动验证

1. **DNS 解析**：批量查 A / CNAME，区分三种结果：解析成功、NXDOMAIN、无记录但 CNAME 存在。附 PTR 反查（IP→主机名）补资产。
1b. **TXT / MX 记录推断 SaaS 与邮件平台**（DNS 查询类别，零目标侧感知；最后核验 2026-09，核验源=对已知组织域的 DNS 实查；**记录名与值均按大小写不敏感比对**——真实记录常为 `MS=ms…` 大写形态）——攻击面扩展点：目标用的每个 SaaS 平台都是潜在的租户接管/子域验证入口（token 悬挂而账号丢失时）。
    - TXT 验证 token 高频项：`google-site-verification`=Search Console｜`MS=ms…`=Microsoft 365｜`atlassian-domain-verification`=Atlassian｜`zscaler-verification-`=Zscaler｜`_amazonses`=AWS SES｜`_dnsauth`=ACME｜workday / shopify / hubspot / docusign / onetrust 同名前缀
    - MX 推断：`aspmx.l.google`=Google Workspace｜`*.mail.protection.outlook`=M365｜`mimecast / pphosted / barracuda`=邮件过滤包裹（真实邮件平台藏在其后）｜自持 IP=Exchange
    - **归属与落点**：这些是组织级资产，不属任何存活子域——站点列记**主域**（与移动端"商店→主域"同构），落报告 §2（不进三产物 CSV）；交接出口 = delivery §5 第五类（SaaS 悬挂验证）
2. **通配符检测（必做，先于一切子域判断）**：查随机子域（`random12345.<域名>`）。解析 ⇒ 存在通配符，此后**不以"解析到通配 IP"剔除任何子域**（vhost——同 IP 不同站点——恰是这类误杀的人群），只把通配 IP 记为可疑标记；去留由 **HTTP 内容基线法**定夺：随机子域响应取 md5 作基线，逐子域比对，内容不同才判真。
3. **HTTP 存活探测**：对解析成功的子域发 GET /，每主机请求预算与并发上限见 SKILL.md 阶段 1 规则（唯一出处），记录状态码、标题、跳转。有 httpx 类工具批量，没有就 curl 循环。
4. **前缀清扫（被动源覆盖不足时）**：对高频前缀表逐个 `dig +short A <前缀>.<域名>`——属 DNS 查询（阶段规则允许的类别），逐条发；**预算与溢出规则见 SKILL.md 阶段 1 规则**。高频前缀：vpn / sslvpn / gp / adfs / intranet / oa / eapps / eproc / tender / sap / erp / crm / billing / dev / test / staging。判据：被动 CT 源实测漏 20-40% 高价值子域（通配证书/无证主机不进 CT 镜像）。被动源充足时不做。
5. **AXFR 区传送（默认不做；仅当授权文件 / 项目规范显式列名允许时执行——可选）**：`dig @<NS服务器> <域名> AXFR`，每 NS 最多 1 发——通过即全量区传送，拒绝即弃。授权未列名 ⇒ 跳过，在备注记"未执行（无授权）"。
6. **递归二级**：首轮发现的子域回灌再枚举一轮（`dev.api.x.com` 类）。
7. **端口扫描：不做**（阶段规则）。授权明确允许且用户要求时作为独立任务另开；测绘引擎的 port 字段与 InternetDB 可间接覆盖。

## 接管嫌疑（只记录，不验证占用；表内指纹最后核验 2026-09，核验源=GitHub `can-i-take-over-xyz` 社区仓库 diff）

CNAME 指向第三方云服务、且该服务返回"资源不存在"类错误 ⇒ 记为接管嫌疑。

| 服务商 | CNAME 指向 | 指纹响应 |
|---|---|---|
| AWS S3 | `*.s3.amazonaws.com` | 404 `NoSuchBucket` |
| GitHub Pages | `*.github.io` | 404 "There isn't a GitHub Pages site here" |
| Heroku | `*.herokuapp.com` | "No such app" |
| Azure | `*.azurewebsites.net` | 默认页 / NXDOMAIN |
| Shopify | `*.myshopify.com` | "shop is currently unavailable" |
| CloudFront | 分配域名 | "Bad request" + X-Amz 头 |
| Tumblr | `*.tumblr.com` | "Whatever you were looking for doesn't exist" |
| Pantheon | `*.pantheonsite.io` | "The gods are wise, but do not know of the site" |
| Webflow | `*.proxy-ssl.webflow.com` | "Site not found" |
| Zendesk | `*.zendesk.com` | "Help Center Closed" |
| Surge | `*.surge.sh` | "project not found" |
| Ngrok | `*.ngrok-free.app` / `*.ngrok.app`（旧 `*.ngrok.io` 已弃用） | "Tunnel not found" |
| Tilda | `*.tilda.ws` | "Please renew your subscription" |
| Fastly | Fastly 边缘 | "Fastly error: unknown domain" |
| Squarespace | `*.squarespace.com` | "No Such Account" |

判据：CNAME 存在 ≠ 可接管（S3 返回 403 = 桶存在且私有，不是嫌疑）；只有"资源不存在"类指纹才算。注册资源验证占用属利用动作，不做。

### 云桶候选（只记录候选名，不发请求）

候选名生成：前缀（backup- / assets- / static- / dev- / prod- / `<公司名>`）× 后缀（-backup / -media / -uploads / -staging / -logs / -private / -dump）。

⚠ **云桶域名（`*.s3.amazonaws.com` 等）不在目标授权范围内**（硬性规则 2：范围外域名只记录不请求）。本阶段只把候选名记入备注列；验证存在性属范围外探测，须用户明确批准后另行执行。

## 排序信号（清单成型后标优先级）

- **关键词分桶**：staging/dev/uat/beta/sandbox/qa（环境）｜admin/portal/internal/dashboard/webmail（管理）｜api/rest/graphql/ws（接口）｜old/v1/v2/legacy/archive/bak（遗留）——环境桶与遗留桶最可能缺维护。
- **共享 IP 聚类**：解析结果按 IP 计数，多子域同 IP 的主机标 top。
- **子域深入优先级**：管理后台 > 开发测试 > 内部系统（vpn/oa/git）> API > Web 应用 > 邮件 > CDN 静态。

**排序即覆盖顺序**（阶段 1 → 阶段 2 的子集规则）：阶段 2 按此优先级在预算内从高到低覆盖存活站点；CDN/静态/邮件默认不做，记入信息缺口（未覆盖原因进报告 §2）。覆盖数 M/N 必须显式报告——"全部存活都做了"还是"做了 top 3"是量级差异，不声明就等于没定。

## 产出

`subdomains.csv`：

```
子域, A记录, CNAME, 状态(存活/不存活/NXDOMAIN/未探测), 来源(crt.sh/wayback/fofa/解析验证/...), 备注(HTTP状态与标题、接管嫌疑、通配符、引擎独有待复核等)
```

状态词为固定取值（权威定义见 references/delivery.md §0）。

## 常见坑

- 未检测通配符就跑子域字典 ⇒ 全部"存活"假阳性；检测后仍须内容基线二次过滤。
- NXDOMAIN 子域不是垃圾：保留在清单里，它们是接管排查对象（只加不减）。
- 多个子域解析到同一 IP ⇒ 可能是 CDN/共享托管；解析所得 IP 与已知 CDN 范围（cloudflare.com/ips-v4、ip-ranges.amazonaws.com 过滤 CLOUDFRONT、Fastly AS54113）交叉核对后才能当源站依据；指纹以每个子域自己的响应为准。
- 归档里的端点可能已死/已重定向/已易主：Wayback 结果复验存活后才进入口清单。
