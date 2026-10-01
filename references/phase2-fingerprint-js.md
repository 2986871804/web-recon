<!-- 阶段 2 实现细节：指纹、JS 下载、接口提取、敏感信息。产出对接见 SKILL.md 数据流；状态词以 delivery.md §0 为准。 -->

# 阶段 2：内容测绘

## §1 组件指纹（从真实响应取，不猜）

| 来源 | 判据示例 |
|---|---|
| 响应头 | `Server: nginx/1.18`、`X-Powered-By: PHP/7.4`、`X-Generator` |
| Cookie 名 | PHPSESSID(PHP)、JSESSIONID(Java)、_rails_session(Rails)、rememberMe(Shiro) |
| HTML | 注释里的版本号、`<meta name="generator" content="WordPress 6.2">` |
| JS 资源路径 | `/static/js/chunk-vendors.*.js`(Vue CLI)、`angular.min.js`；sourcemap 存在 = 开发配置残留 |
| 报错页 | Spring Boot JSON 错误体、Tomcat 堆栈、框架原生 404 体 |
| 缓存层头 | `Via: 1.1 varnish`、`X-Cache: Hit from cloudfront`、`Cf-Cache-Status`、`Age` |

指纹记录格式：**组件名+版本串**（如 "Spring Boot 2.x / nginx 1.18 / Vue 2.6"）——后续漏洞比对的锚点。

### §1.1 中间件与设备路径矩阵（逐路径 1 发 GET，403 / 404 也记录）

| 类别 | 探测路径 | 备注 |
|---|---|---|
| Tomcat | `/manager/html`、`/host-manager/html` | 401 = 存在且设防；默认口令只记录存在性，不登录 |
| JBoss / WildFly | `/jmx-console/`、`/web-console/` | |
| WebLogic | `/console/`、`/wls-wsat/` | |
| Jenkins | `/script`、`/manage` | |
| Spring Boot Actuator | `/actuator/` 系列 | 优先级见下 |
| GlassFish / Jetty / Resin | `/common/`、`/jolokia/`、`/resin-admin/` | |
| 容器 / CI-CD（**路径级探针，不做端口扫描**——仅当服务暴露于 80/443 或反代后可见；开放端口本身用 phase1 的被动端口观察取） | Jenkins `/api/json`（匿名可读性）、GitLab `/api/v4/version`、Argo CD `/api/version`、Harbor `/api/v2.0/projects`、Docker `/version`、kubelet `/pods`、etcd 经反代 `/v2/keys/` | 命中即记录版本与匿名可达性，不深度枚举 |
| Citrix | `/vpn/index.html` | 边缘设备类，命中即记录型号 |
| F5 BIG-IP | `/tmui/login.jsp` | |
| FortiGate | `/remote/login` | |
| PaloAlto | `/global-protect/` | |
| vCenter | `/vsphere-client/` | |
| Exchange | `/owa/`、`/ecp/` | |

Actuator 端点优先级（只读取证，不利用）：

```
/actuator/env           环境变量（DB 凭据、key）
/actuator/heapdump      JVM 堆（内存中的口令；下载取证，不利用）
/actuator/mappings      全部 URL 映射——直接并入接口清单
/actuator/configprops   配置属性
/actuator/beans /actuator/threaddump
/actuator/gateway/routes   记录存在即可
```

### §1.2 泄露路径清单（每项 1 发 GET；预算数值的唯一出处 = SKILL.md 阶段 2 规则（此处不复制，防漂移）；最后核验 2026-09，核验源=recon-skills `probes-and-wordlists` / HackTricks 同类仓库 diff——路径表只加不减，核验重点是"新框架要不要加"而非删旧）

**探测顺序**（§1.1–§1.3 合计路径数超预算一倍，按此优先级花预算，超即停）：① catch-all 基线 1 发（§1.4）→ ② robots.txt / sitemap.xml → ③ §1.3 API 文档族（命中即高价值）→ ④ 按已命中指纹选 §1.1 矩阵对应行（Java 栈才探 Java 行，不盲扫全表）→ ⑤ §1.2 其余按余量。未探测路径记入未闭环清单（信息缺口），不算丢弃。

```
版本控制/备份： /.git/HEAD  /.git/config  /.svn/entries  /.DS_Store
              /backup.zip  /www.zip  /db.sql  /config.php.bak  /.env  /.env.bak
              后缀变体：.bak .old .orig .swp ~ .tar.gz .7z .sql（文件名 × 后缀组合）
构建/依赖：    /composer.lock  /package-lock.json  /yarn.lock  /Gemfile.lock
              /Dockerfile  /docker-compose.yml  /Procfile  /web.config  /.htaccess  /nginx.conf
CMS 专项：     /wp-config.php.bak  /wp-content/debug.log  /wp-json/wp/v2/users（用户枚举）
              /CHANGELOG.txt（Drupal 版本）  /readme.html
管理/调试：    /pma  /_phpmyadmin  /server-status  /server-info  /phpinfo.php  /debug/
策略/元信息：  /robots.txt（Disallow 值=专属路径清单）  /sitemap.xml（全 URL 列表）  /crossdomain.xml
              /.well-known/security.txt（组织信息/邮箱）
API 文档：     见 §1.3
```

### §1.3 API 文档与 schema 探测

| 框架 | 路径 |
|---|---|
| Swagger 通用 | `/swagger-ui.html`、`/swagger-ui/`、`/swagger.json`、`/api-docs` |
| Spring (springfox) | `/v2/api-docs`、`/v3/api-docs`、`/swagger-resources/configuration/ui` |
| FastAPI | `/docs`、`/redoc`、`/openapi.json` |
| .NET (NSwag) | `/swagger/v1/swagger.json`、`/api/swagger/v1/swagger.json`（常挂在 /api 下，根路径 404 ≠ 无 spec） |
| Quarkus | `/q/openapi` |
| 通用 | `/.well-known/openapi.json`、`/application.wadl`（JAX-RS 遗留） |
| GraphQL | `/graphql`、`/gql`、`/graphiql`、`/api/graphql`、`/v1/graphql`、`/altair`、`/playground` |

- 命中 swagger / openapi：提取未文档化字段、admin 请求示例、弃用但仍活跃的端点、与过滤/排序/ID/租户相关的参数名，`components.schemas` 里的权限字段（isAdmin/role/tenantId）；`jq '.paths|keys'` 直接出端点清单。
- GraphQL 命中：introspection **仅当站点支持 GET 查询串形态（`?query=`）时**执行 1 发确认可否匿名执行；仅接受 POST 的（硬性规则 1 禁发）记录"存在但未测"，不做深度查询；UI 残留标记（响应含 graphiql/playground/altair 字符串）记录。
- 版本漂移：`/api/v1/`、`/api/v2/`、`/api/mobile/v1/`、`/legacy/` 各挑 1 个代表路径确认存活。

### §1.4 命中确认签名 + catch-all 基线（防"200 即泄露"误报）

1. **先打 catch-all 基线**：GET `/<随机串>-check-xyz`。返回 200 + HTML + >500B + 无敏感关键词 ⇒ 该站是 catch-all（任意路径都 200），**本站所有"200 = 命中"的判定作废**，只能靠内容签名判。
2. **每路径内容确认签名**（200 之外的第二判据）：

| 路径 | 必含内容 |
|---|---|
| `.git/config` | `[core]` 或 `repositoryformatversion` |
| `.env` | 多行 `[A-Z_][A-Z0-9_]*=` 结构 |
| `.DS_Store` | `Bud1` 魔数 |
| `/actuator/env` | `"propertySources"` |
| `/server-status` | "Apache Server Status" |
| phpinfo | "PHP Version" |

### §1.5 指纹规则库（GitHub 现成资源，离线比对）

指纹不自己维护矩阵——用社区维护的规则库对**已落盘的响应集**做离线匹配，零新增请求：

| 规则库 | 内容 | 匹配位置 |
|---|---|---|
| 0x727/FingerprintHub | 国内外中间件/OA/CMS 的 JSON 规则，按产品分文件 | path + header + body 关键字 |
| EHole_magic（lemonlove7，EHole 魔改版） | 红队常用指纹库 | title / body keyword / favicon hash |
| Wappalyzer 规则（technologies.json） | 通用技术栈，含 implies 推导链；httpx `-tech-detect` 内置同源规则 | header / cookie / html / meta / script src |
| whatweb 插件（~1900 个） | 插件式匹配 | header / body / url / 版本正则 |
| nuclei-templates `http/technologies` | 模板化技术检测 | 任意请求-响应组合 |

流程：

1. 备响应集：已落盘的响应头 + 正文（首页、错误页、静态资源）+ favicon。
2. 克隆/更新规则库到工作目录（`git pull`），**报告注明所用库与 commit**——指纹结论依赖规则库版本。
3. 逐规则在响应集上匹配：规则 =（位置，特征串/正则，产品名，可选版本正则）。命中 ⇒ 指纹表加一行：产品+版本+证据（规则来源 + 命中的响应文件）。
4. 规则要求特定 path 的响应而本地没有的（如 /actuator/env 确认 Spring），回到 §1.1 矩阵逐路径 1 发补齐——矩阵与规则库是互补关系：矩阵保底高频路径，规则库管广度。
5. favicon hash：favicon 内容 base64 后取 mmh3。hash 直接用于测绘引擎反查（FOFA `icon_hash=""`、Shodan `http.favicon.hash:`），同 hash 的其他资产常属同组织。

口径：不复制规则内容进本技能（会过时）；版本串以响应原文为准，规则正则提取的版本写进证据。

## §2 下载全部 JS —— 校验完整性

大 JS 文件可能只下载一部分：HTTP 200、退出码 0，工具不报错。基于残缺文件的提取会漏接口。

- 用 `scripts/safe_fetch.py`：`python scripts/safe_fetch.py --base https://<host> --urls urls.txt --out ./dl --retry 6`（走代理加 `--proxy http://127.0.0.1:8080`）
- 判定标准一条：**实收字节数 == 响应头 Content-Length**。不符重下。chunked 传输（无 CL）→ 判定 CHUNKED：**可用于提取**、产物标注"不可校验"，不进重试（重试也长不出 CL）。
- 经验阈值：>700KB 的文件重点盯。
- 残缺的隐蔽症状：webpack 产物里出现"被引用但找不到定义"的模块 id——第一反应是文件没下全，不是"存在隐藏模块"。
- 构建漂移检测：同一主文件下 3 次比对哈希；同一地址返回不同内容 ⇒ 后端多节点版本不一致，记录。
- **chunk 清单入口**（拿全量 JS 文件名）：`/asset-manifest.json`、`/webpack-manifest.json`、`runtime~main.*.js`（runtime chunk 含全部 chunk 映射）；抓不到清单时按常见名兜底猜路径：`/main.js /app.js /bundle.js /runtime.js /vendor.js /_next/static/_buildManifest.js`。
- **二跳补抓（必做）**：对已下载文件 grep 引用的 `*.json`（i18n 语言包）、`*.css`（webpack CSS chunk）、懒加载 chunk 名（`import(` / webpackChunk），追加进 urls.txt 第二轮拉取——语言包、CSS chunk 与懒 chunk **都不从首页引用**，不主动拉永远拿不到（本地 `--dir` 已能扫 .css，前提是文件先拉下来）；语言包高频藏接口名与权限词（passwordlessLogin / export / permission），是免鉴权候选的天然字典。
- **扫描范围与跳过计数**：`extract_endpoints.py --dir` 递归吃 js / mjs / cjs / ts / tsx / jsx / vue / json / html / htm / css / map 十二类文本（三个提取/扫描脚本均为递归 walk）；非文本文件计入"跳过 N 个"汇总——**无静默丢弃**（实测教训：只吃 .js 时 zh-CN.json 里 3 条接口被无声跳过）。
- **下载判定联动（机械执行）**：提取器递归发现任意层级的 `_fetch_report.json`（safe_fetch 的报告常在 `./dl/` 子目录）——非 OK 判定（TRUNCATED / CL_MISSING / FAILED / HTTP_4xx）的文件**不进入提取**，排除计数入汇总；4xx 错误页里的 href 是支持链接/跳转目标，只记"存在被拦"信号，不进接口清单。判定文件自身同样不进提取。**报告损坏的降级三件套**：① 显式告警（含路径与异常原因，不静默停摆）；② `.hdr` 侧车重建判定——safe_fetch 给每个下载写自包含侧车（首行 `Status: <code>` + 响应头），报告损坏时按 Status+Content-Length 完整重建 verdict（覆盖 TRUNCATED 与 4xx；旧版无 Status 行的侧车退化为仅截断校验）；③ **退出码 1**（对齐 safe_fetch 约定：0=正常，1=结果未经过滤），链式调用可机械检测降级。剩余边界如实声明：**无 .hdr 的文件无法复核**（外部来源文件），已进入提取。报告与侧车读取均容 BOM（utf-8-sig，同一宽容度）。"无报告"是正常态不走降级。三个提取/扫描脚本行为一致，`--files` 与 `--dir` 走同一条过滤路径。
- **内容嗅探兜底**：无判定文件时，.js 路径存成 HTML 错误页按 HTML 形态处理——扩展名与内容形态脱钩不再整页静默漏。
- **sourcemap**：JS 尾部 `sourceMappingURL=`；**内联形态**（`sourceMappingURL=data:application/json;base64,...` 打进 JS 本身）base64 解码即得完整 map——比外链 .map 更隐蔽且常被忽略；历史 map 用 Wayback CDX `filter=original:.*\.js\.map$` 挖。三种来源的 `sourcesContent[]` 都是前端完整源码（含后来删除的硬编码密钥、内部接口、注释）+ 源码文件清单，**完全离线零新增请求**。仅取有明确引用或已存在的 map，不盲猜路径。

### §2.5 历史响应体回捞（零新请求的第三数据源）

CDX 只取 `fl=original` 等于把归档用了一半。完整姿势：

```bash
# 字段集扩到 时间戳/状态码/mimetype，按 JSON 过滤出 API 响应：
curl "web.archive.org/cdx/search/cdx?url=<域名>/api*&fl=original,timestamp,statuscode,mimetype&filter=statuscode:200&collapse=urlkey"
# 回捞原始响应体（id_ 后缀 = 原始字节，无 Wayback 改写）：
curl "web.archive.org/web/<timestamp>id_/<original_url>"
```

价值与边界：

- **能拿**：历史 GET 的完整响应体（接口包络、字段结构、脱敏前的数据形态）、URL 查询串参数（随 original 完整保留）——参数结构的系统化来源，补手工填参。
- **拿不到**：POST 请求体。Wayback 的 capture 单元是爬虫的 GET 响应，请求载荷不入库；CDX 也无 method 字段。别去归档里找提交表单的 POST。
- 归档端点可能已死/已易主：回捞结果照常进入口清单（来源=归档），复验存活后才算已验证。
- 请求对象是 web.archive.org（第三方），不占目标预算；对归档端保持 ≤1 请求/秒。

## §3 接口提取：静态路线（必跑）

```bash
python scripts/extract_apis.py <js目录>          # 粗筛：分级+调用点分类
# 精提（多站点：按站点目录分次运行，每次 --site 传该站点——归属生成时打标）：
python scripts/extract_endpoints.py --dir <站点dl目录> --site <存活子域> --hidden --csv out.csv
```

提取规则：

1. **正则产出只是嫌疑名单**。高价值条目取上下文 ±150 字符核验是不是真调用点——局部匹配会把 SDK 错误码常量误判成接口。
2. **`url:` 不一定是首键**，方法键可能是复数 `methods:`——匹配任意位置的 `url:`。
3. **路径里的动态段保留占位符**：`"/a/".concat(id, "/b")` 的正确还原是 `/a/{id}/b`，不是 `/a/b`——后者既多报（伪路径）又漏报（真前缀丢失）。反过来，**纯字符串字面量之间的裸 `+` 是确定性拼接**（合法 JS 里唯一解释），直接连接不产占位符——占位符语义是"需填写的动态段"，空拼接点标 `{expr}` 会让阶段 3 拿必 404 的假路径探测。
4. **不以 `/` 开头的接口路径是真实存在的**（`url:"face/batchImport"`），归一化补 `/`，不过滤。
5. **隐藏接口第二遍**（`--hidden`）：上传组件的 `action:`、`uploadUrl = "..."` 等 **`:` 键与 `=` 赋值两种形态都收**（赋值取值带语句边界与 ASI 续行启发）的变量承载地址不经过 axios 封装，只扫 `url:` 必漏；变量声明与调用点分处两地，要配对反查。
6. **交叉验证防噪声**：隐藏形态的命中若与已知接口零重合，先怀疑规则误抓（图表库/播放器内部字段），不急着入清单。
7. **框架调用点正则**（正则法补充）：Vue `(axios|this.\$http|fetch|request)\.[a-z]+\(['"]([^'"]+)`；Angular `this\.http\.[a-z]+[<(]\s*['"]([^'"]+)`。
8. **WebSocket / SSE / GraphQL 通道**：`new WebSocket(...)`、`new EventSource(...)` 的值表达式按占位符规则重建（方法列记 WSS / SSE）；`wss?://` 字面量记形态 wss-url；`operationName:` 记形态 graphql-op（配合 /graphql 端点用）。均有提取产出，不再只是规则承诺。
9. **前缀常量回填**：`{API_HOST}` 类前缀占位符对照全文件常量表（`NAME = "https://..."` / `wss://`）自动回填基址并剥占位符；表里没有才标"需人工解析"。占位符在路径中段的不剥（防破坏路径）。

**盲区可见性（两件机械防线 + 一条诚实边界）**：

1. **通道健康直方图**：精提报告固定打印各通道命中数（**零也在场**）——某通道整库为 0 本身是信号（裸 fetch 盲区修复前 fetch 恒 0 而无人看见）。
2. **粗筛/精提对账**：`extract_apis.py <目录> --reconcile-fine <精提CSV>`——粗筛抓到而精提漏掉的路径被点名（"盲区候选，人工复核前不得丢弃"）。此前这道对账由人工承担，裸 fetch 正是粗筛兜住、精提漏掉、无人 diff 才静默存活到 eval 才暴露。
3. **诚实边界（Class B）**：语义级拼装（分段/Base64/动态计算路径）任何形态探测器都不可见——这是三道闸（粗筛→精提→人工）+ evals 存在的理由，不是缺陷而是边界；新增前端形态时优先靠 eval 新用例驱动补通道，再靠直方图与对账守护已补的通道。

**参数名来源（入口清单「参数」列的三个来源，不再手填）**：① `extract_endpoints.py` CSV 的 `参数名` 列（url 容器对象里 `params:{...}`/`data:{...}` 的键名）与 `query` 列（URL 字面量查询串）；② 归档 URL 查询串（§2.5）；③ 语言包/配置里的权限词仅作候选排序线索，不当参数。路径占位符（`{id}`）在路径列，不与参数混。

## §4 接口提取：运行时路线（有浏览器时）

静态看不到的：运行时拼接的 URL、服务端下发的配置、需要交互才触发的调用。

1. **页面资源清单**（页面打开后执行）：
   ```js
   [...new Set(performance.getEntriesByType("resource").map(e => e.name))]
   ```
2. **网络钩子**：注入 `scripts/hook_inject.js`（控制台粘贴即可）→ 正常操作页面 → 从 `window.__cap` 收割 method/headers/body/response 成对数据。
3. **SPA 路由表**：
   ```js
   window.$nuxt.$router.options.routes                                // Nuxt2：全部路由，含菜单不可见页
   document.querySelector('#app').__vue__.$store.state                // Vue2
   document.querySelector('#app').__vue_app__._context                // Vue3
   __BUILD_MANIFEST.sortedPages                                        // Next.js（控制台）：含动态路由 /[slug]
   ```
   路由表与可见菜单做 diff，发现隐藏功能页（提交页/管理页类）。`/#/` 片段路由普通 HTTP 重取只能拿到根文档，需无头浏览器物化。
4. **覆盖范围**：钩子只捕获客户端发起的请求；服务端渲染页面的数据在 HTML 里（`__NUXT__` / `__NEXT_DATA__` / `window.__CONFIG__` / `window.__INITIAL_STATE__`），零客户端请求是正常现象，读注水数据。跨域整页跳转会杀掉钩子，需重注入。
5. CSS 也过一遍：`url()` 引用、`@import`、CSS 内 sourcemap 引用（常漏的资产与域名来源）。

## §5 定位真实 API 基址（不猜）

按顺序在 JS 里找：

1. axios 封装模块的 `baseURL:`（grep `baseURL:[^,]{0,40}`）——顺带拿到鉴权头格式、成功判据、超时。常见鉴权头形态记录进入口清单备注：`Authorization: Bearer`（OAuth2/JWT）、`X-API-Key`、`X-Auth-Token`、自定义 token 头。
2. 主机常量导出表 / 租户配置（grep `API_HOST`、`_HOST =`、`Host:"https://`）——常一次读出全部后端域名与 Cookie 作用域。
3. 构建时注入的环境变量：`NODE_ENV:"production"` 附近 900 字符；**前端构建前缀** `VITE_*` / `REACT_APP_*` / `NEXT_PUBLIC_*`（dev 配置残留时整组泄露，如 VITE_JWT_SECRET）。
4. 后端托管平台模式：`*.fly.dev / azurewebsites.net / vercel.app / netlify.app / supabase.co / r2.dev`——`dpl_*`（Vercel 部署 ID）与 Supabase anon key 是公开值，只记 URL 不当密钥。

域外接口只记录，标注「需另行授权」，不请求。

## §6 敏感信息 grep（本地跑，零请求）

对已下载的 JS/HTML 查：

| 类别 | 模式 |
|---|---|
| 云/厂商密钥 | `AKIA[0-9A-Z]{16}`(AWS)、`ghp_`/`github_pat_`、`sk-ant-`/`sk-proj-`、`xox[abpors]-`(Slack)、`SG\.\w+\.\w+`(SendGrid)、`dop_v1_`(DO)、`hf_`、`npm_`、`dckr_pat_` |
| 通用 | JWT（`eyJ` 长串）、`BEGIN .* PRIVATE KEY`、DB 连接串 `(mongodb|mysql|postgres)://`、`wss?://` 端点 |
| 变量名 | `JWT_SECRET`、`secretKey`、`salt`、`getSign`、`CryptoJS`、`JSEncrypt` |
| 内网 | RFC1918 段；内部域名 TLD `\.(internal|corp|lan|intranet|local|prod|staging|dev|qa)\b`；K8s DNS `[a-z0-9\-]+\.[a-z0-9\-]+\.svc(.cluster.local)?` |
| 第三方 | SDK 的 app_id、云账号 ID `arn:aws:\w+:\w*:(\d{12}):` |

**防误报**（报泄露前先看上下文 40 字符）：

- "手机号"大批量命中 ⇒ 可能是毫秒时间戳的前 11 位；加前后非数字边界再数。
- "内网 IP" ⇒ 可能是抓包代理自己写在错误头里的本机地址。
- 取字段值前先 dump 一条完整记录看结构——真实值常在嵌套子对象里。
- **公开标识 ≠ 密钥（定级规则，非排除规则）**：client_id、`dpl_*`、Supabase anon key、README 示例串——**永不入密钥级/高危级结论**；可作为**低级别**行入 leaks.csv（情报值：指向目标所用 SaaS 平台，是交接协议第五类 SaaS 悬挂验证的线索源），备注必须标「公开标识」。曾因与 delivery §1.5 类别枚举措辞互相矛盾导致两轮代理行为随机翻转（一轮全排除、一轮记为泄露）——本条为唯一权威。
- 发现疑似真实密钥：记录证据即可，**不验证 live/dead**（用密钥调第三方 API 属后续独立任务，须用户批准）。

### §6.1 注释敏感线索（独立通道：`scripts/scan_comments.py`）

正则形状的密钥全文 grep 能撞上（不分注释与否），但**注释里**的三类没有形状可撞，只能按"注释 + 触发词"找：

| 类别 | 形态 |
|---|---|
| 中文/英文凭据 | 触发词（密码/口令/账号/用户名/凭据/密钥/secret/token/apikey…）+ 紧随的值 |
| 内网裸地址 | RFC1918 段（可带端口）+ `.internal/.corp/.lan/.local` 主机名 |
| 注释掉的旧接口 | `/api|web|gateway…` 前缀路径——**废弃线索**，与提取器正常产出语义不同 |

```bash
python scripts/scan_comments.py --dir <文本目录> --csv clues.csv
```

- **独立产物通道**：产出 `注释线索清单`，**不并入泄露点清单**——线索 ≠ 已确认泄露，核验（上下文+实际请求）后才升级。混淆会污染定级。
- **内网 IP 二道判据（置信列）**：形状命中后看语境——伴随 内网/网关/直连/端口/URL/服务器 等线索词 ⇒ 高置信；版本号/UA/时间戳语境 ⇒ 低置信；同值多语境出现置信只升不降。核验按高置信优先。
- license 抑制内置：`@license / Copyright / Licensed under` 横幅整块滤除，重复横幅合并计数，不刷屏。
- 文件覆盖：js/ts/css 家族（`//` 与 `/* */`）、HTML（`<!-- -->`）、**.vue 双区**（模板 HTML 注释 + 脚本 JS 注释都扫）；JSON/.map 无注释语法，跳过并计数；行号+上下文随线索给出。
- **证据本体规格**：上下文只来自所属注释块（不跨块、license 等已滤块不得倒灌），换行以 `⏎` 显式标记——上下文、行号、块内容三者必须互相印证，不得把多行伪装成一行。
- 阴性也要报："注释 0 命中"是有效结论（历史上验证过整站注释无隐藏接口）。

## §7 源码与文档侦察（零目标流量；查询对象是第三方平台，性质同阶段 1 被动源，SKILL.md 步骤⑧授权）


- GitHub 组织仓库：`api.github.com/orgs/<org>/repos?sort=updated` 看 visibility——新公开仓库即潜在泄露。
- 代码搜索 dork（gh CLI 或网页）：`org:<目标> password`、`org:<目标> api_key`、`org:<目标> "BEGIN PRIVATE KEY"`、`filename:.env`、`"<域名>" password`。
- 协作文档：`site:notion.site OR site:atlassian.net OR site:trello.com OR site:miro.com "<目标名>"`。
- 结果分级：URL 含 `.pem/.p12/.key/id_rsa` = 高；仅代码片段命中 = 待确认，须访问复核后才入清单。

## §8 移动端资源静态提取（本地零目标流量；apk 下载本身是静态资源 GET，属既有授权类别）

移动端是常被忽略的接口面：更新滞后（比 Web 前端旧几个版本的 API 仍在用）、硬编码 key、内部/测试环境域名高频出现。

获取：站点提供的 apk 直链（常见于 `/download`、`/app` 页——页面与静态资源请求 ✓）；应用商店页元信息（平台侧查询）。IPA 一般无公开直链，拿到再处理。

APK 分析阶梯（按工具可用性降级，最低 strings 保底）：

1. `unzip app.apk -d apk/`——无任何工具的第一步：`AndroidManifest.xml`（二进制，strings 仍可读出 deeplink scheme）、`assets/`、`res/` 里的配置与 JS bundle（混合应用常带完整前端）。
2. 有 apktool/jadx 时：反编译拿 Manifest 明文（**exported 组件 + deeplink `scheme://host/path` = 隐藏 API 面**）、smali/java 里 grep okhttp/retrofit 的 base_url 与常量。
3. 保底：`strings classes*.dex | grep -E 'https?://|/api/' | sort -u`——纯本地，任何环境可跑。

iOS IPA：`unzip app.ipa` → `Payload/*.app`：`Info.plist` 的 URL schemes、主二进制 `strings | grep` URL 与域名。

产出并入既有通道（不新建产物）：接口/路由 → 入口清单（**来源=移动端提取**，站点取值见 delivery §1.5 三态规则：直链→该站点、商店→主域、用户提供→`-` 且备注写提供者）；密钥 → leaks（备注"来自 apk"+站点同样按三态）；内网域名/旧环境 → clues。deeplink 记录 scheme+host+path 于备注。

红线：只做静态解包 + 本地 grep（零目标流量）；模拟器动态运行 / 移动端抓包属后续独立任务，须另行批准。

## 产出


- 指纹表（组件名+版本串+证据响应头；含 §1.1–§1.4 命中记录）
- `入口清单.csv` 新增条目：URL、方法、参数（来源见 §3 参数名来源）、基址归属、来源（静态/运行时/归档/移动端/两源重合），状态=未验证（词表见 delivery.md §0）；`wss://` 命中同入清单（方法列记 WSS，状态未验证）；备注可标高价值类别（admin/internal/debug、upload/import/export/download、user/account/order 类 IDOR 高发、search/query/filter 类）
- 泄露点清单（每条附 40 字符上下文证据）
- 注释线索清单（§6.1 独立通道产出：中文凭据/内网裸地址/注释旧接口；核验后才升级进泄露点清单）
- 报告尾含**反查索引**（接口 → 全部来源文件，完整不截断）——400 个 chunk 时定位"这条接口是哪个 chunk 贡献的"不再人肉翻列
