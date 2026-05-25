VeriHash.org：AI 原生职业信用节点开发路线图
=============================

**愿景 (Vision):** 构建一个零摩擦（免注册、免登录）、由 DID 签名驱动的“公共中继与解析节点 (Accountless, DID-signed public relay)”，为知识工作者提供对 AI 爬虫极度友好的公开广播网络。
阶段一：MVP（核心跑通与基础防御）- 单兵作战期
-------------------------

**目标：** 跑通“本地软件 -> 官方节点”的数据流，建立标准化的 RESTful API，并部署最低限度的物理防线。

**核心原则：** 极简后端、稳妥的数据持久化、严谨的 API 规范。

### 1. 极简服务端建设 (API 节点)

* **技术栈修正**：
  
  * **后端**：Go (标准库 `net/http` 或 Gin)。
  
  * **部署与持久化**：**严禁在无状态 Serverless 上使用 SQLite**。建议方案 A：廉价固定 VPS + SQLite + 每日备份；建议方案 B：Vercel (前端+API) + Supabase (免费 PostgreSQL 数据库)。

* **RESTful 核心接口**：
  
  * `POST /v1/credentials`：接收 `pubkey`, `payload`, `signature`。验证签名通过后落库。
  
  * `POST /v1/revoke`：接收带有新签名的撤销指令，原地覆写/删除原始数据，并在索引中立碑（Tombstone）。
  
  * `GET /u/{did}/profile_index.json`：获取该 DID 的公共根索引与凭证清单。
  
  * `GET /u/{did}/credentials/{vc_id}.json`：获取单条具体凭证。

* **基础防刷防线 (Anti-Spam MVP)**：
  
  * 单条 Payload 大小硬性限制（例如 < 50KB）。
  
  * 单 IP 每小时请求限制（防止纯机器扫描）。
  
  * 单 DID 每日提交上限（如每日最多 20 条），防止本地客户端脚本化恶意灌水。

### 2. 客户端改造 (VeriHash Go/Wails)

* **UI 更新**：在 `Settings` 添加 `Broadcast Channel` 下拉菜单。
  
  * 选项 A：`VeriHash.org Official Relay`
    $$默认推荐$$
  
  * 选项 B：`GitHub Gist (Requires Token)`

* **通信逻辑**：适配新的 `/v1/credentials` 接口，完成签名和 JSON 序列化后推送。

阶段二：AI 原生化与极简视觉层
----------------

**目标：** 提供业界最标准的 AI 阅读入口，并确立专业、中立的 UI 视觉语言。

### 1. 明确的机器阅读标准 (Deterministic AI-Readability)

* 放弃脆弱的 User-Agent 嗅探，直接提供标准化的物理入口。

* **`llms.txt` 标准集成**：提供 `GET /u/{did}/llms.txt`。以纯 Markdown 格式汇总该用户的核心技能点与最近的工作摘要，专供 LLM 一键读取。

* 部署 `robots.txt`，主动放行所有合法爬虫。

### 2. 极简专业视觉 (Human Interface)

* **人类访问入口**：`GET /u/{did}`。

* **UI 调性修正**：放弃过度“赛博朋克”的黑底绿字。面向律师、咨询师等高信任职业，采用**白底/浅色中性底色、大片留白、极简排版 (Minimalist & Professional)**。

* 仅保留那个“莫比乌斯环”作为画龙点睛的品牌信任锚点。

阶段三：开放协议与治理 - 秩序建立期
-------------------

**目标：** 将平台抽象为协议层，支持第三方接入，并升级防黑客风控策略。

### 1. Schema 协议开源与生态扩展

* 在官网正式发布 `VeriHash Credential Schema (JSON)` 数据字典规范。

* 宣布 VeriHash.org 成为“开放协议平台”，支持社区开发的 VS Code 插件、Notion 插件直接使用私钥签名向 `/v1/credentials` 推送数据。

### 2. AI 巡逻风控机制 (AI-driven Moderation)

* 对于平台涌现的大量凭证数据，引入后台 Cron Job。定期利用大模型（如 Gemini Flash）抽查新增数据的“上下文逻辑连续性”。

* 对于检测出明显由脚本随机生成的无意义“哈希垃圾”链，将该 DID 标记为 `banned`（Shadowban 折叠机制）。

阶段四：去中心化互操作 (长期愿景)
------------------

**目标：** 让数据真正具有流动性，并支持个人品牌深度定制。

### 1. Nostr 协议桥接 (Nostr Relay Bridge)

* 增加选项：服务端接收数据后，自动封装为 Nostr Event (NIP-01)，中继到全球 Nostr 极客网络中，实现真正的抗审查存储。

### 2. 个人品牌增强

* 支持基于 DID 的简短化域名解析（如 `verihash.org/brian` 自动关联其 Pubkey）。

* 为高阶用户提供自定义域名的 CNAME 绑定能力（如 `proof.briansuin.com` 映射到官方解析层）。

> **给 Brian 的行动建议 (Action Item)：**
> 
> 现在的路线图已经排除了致命的工程隐患。接下来，你需要先搞定 **数据库选型（VPS or Supabase）**，然后就可以动手用 Go 糊那几个 `/v1/` 接口了！
