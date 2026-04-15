# 🗺️ VeriHash Nexus v0.2-4 产品架构与开发路线图

**产品定位**：AI 时代的工作量公证机，脑力劳动者的可验证身份基础设施。   
**核心受众**：律师、研究员、独立开发者、法律极客、跨境合规专家。   
**战略切入**：单机存证工具开局，多信道 AI-Web 广播收尾，最终构建无需信任的代理社交层。   
**开源承诺**：用户永远不会把核心资产托付给一家他们无法审计代码的公司。

**隐私模型**：AI 引擎只见文件名 \+ 智能提取的修改片段，**完整敏感原文永不离开用户设备。本地文件与云端文件遵循完全相同的处理逻辑。**

---

## 🧱 Phase 1：物理基建层 (The Silent Sentinel)

**状态：✅ 已完成**

| 模块 | 机制 | 状态 |
| :---- | :---- | :---- |
| 身份引擎 | Ed25519 公私钥对，DID 本地生成，私钥永不离机 | ✅ |
| 静默监听引擎 | fsnotify 守护进程，监听绑定工作区目录 | ✅ |
| 时间序列账本 | SQLite，记录 (时间戳, 文件增量, 当前哈希, 上一哈希) | ✅ |
| 工作区管理 | 多目录绑定，拖拽添加，FLUSH 清空，全路径 Tooltip | ✅ |

**新增 — 云端同步目录智能识别**：添加工作区时自动检测云存储同步路径并标记图标：

C:\\Users\\\[User\]\\Google Drive\\My Drive\\  →  标记 \[GDRIVE\]

C:\\Users\\\[User\]\\Dropbox\\                →  标记 \[DROPBOX\]

C:\\Users\\\[User\]\\OneDrive\\              →  标记 \[ONEDRIVE\]

---

## 🧠 Phase 2：可插拔 AI 评估层 (The Pluggable Oracle)

**状态：✅ 已完成（含架构修正）**

**核心战略修正**：放弃"本地 AI 优先"，采用"**云端默认 \+ 选择性披露**"。实践验证本地小模型性能不足，而只要保持智能摘录机制，云端 AI 的隐私边界同样可以接受。

| 引擎 | 类型 | 推荐模型 | 价格参考 |
| :---- | :---- | :---- | :---- |
| LOCAL::Ollama | 本地 | phi3 | 免费，性能受限 |
| CLOUD::Gemini | Google 原生 | gemini-2.5-flash | $0.075/1M tokens |
| CLOUD::DeepSeek | OpenAI 兼容 | deepseek-chat | $0.014/1M tokens |
| CLOUD::Qwen 千问 | OpenAI 兼容 | qwen-turbo | $0.003/1M tokens |
| CLOUD::MiniMax | OpenAI 兼容 | MiniMax-Text-01 | 较低 |
| CLOUD::OpenAI | OpenAI 原生 | gpt-4o-mini | $0.15/1M tokens |
| CUSTOM::Endpoint | 用户自定义 | 任意 | 企业内网/私有部署 |

安全徽章：`[ 100% OFF-GRID ]` → 本地 Ollama ｜ `[ CLOUD API ]` → 云端引擎（仅修改片段外发）

### ⚠️ 2.x 智能 Diff 提取算法（隐患修正，待开发）

**背景**：当前字节截断（前 8KB）对法律合同等大型文档完全失效——修改点可能在第 40 页，截断前 8KB 只能得到封面，AI 总结毫无意义。

**修正方案**：Watchdog 在将内容送往 AI 之前执行三层智能提取：

| 文件类型 | 处理策略 |
| :---- | :---- |
| 纯文本（`.txt/.md/.js/.go` 等） | 计算 unified diff hunk，只提取**被修改段落 \+ 前后 3 行上下文** |
| Office 文档（`.docx/.xlsx`） | 先提取纯文本层，再执行 diff hunk 算法 |
| PDF | 提取文本层（PDFium），再执行 diff hunk 算法 |
| 首次铸造（无历史对比） | TF-IDF 关键段抽取，优先保留信息密度最高的段落 |

**双重收益**：① 隐私更强——未修改的机密原文从不离机 ② Token 消耗更低——实质性修改通常只有 200-500 字的 diff

---

## 📜 Phase 3：单机变现层 (The Trojan Horse)

**状态：🔄 JSON 导出已完成，HTML 卡片待开发**

### 3.1 极客战报导出器 🔥 最高优先级

一键将 VC 渲染成赛博朋克风格的 `.html` 静态凭证卡片：

- AI 评估摘要 \+ 技能标签云  
- GitHub 风格工作量展示区块  
- 底层哈希链证明（极客展示用）  
- 内嵌 JSON-LD 结构化数据（机器可读，SEO 友好）

**战略意义**：用户拿着这张卡片去交付工作，通过"实力碾压"实现人传人的自然裂变。

---

## 📤 Phase 4：多信道凭证发布层 (The Broadcast Network)

**状态：📋 规划中**

每次铸造后，账本条目显示已发布的信道徽章：`[LOCAL] [HTML] [GDRIVE] [IPFS] [NOSTR] [WEB] [GIST]`

### 4.1 本地文件系统

自动保存 `credential_[date]_[vcid].json` 和 `.html` 凭证卡片到用户指定目录。

### 4.2 云端存储平台双向集成 ⭐ 战略核心，🔥 优先级提升

**架构重定位**：此模块不只是"发布渠道"，更是**解锁云端文档内容型存证的核心基础设施**。本地文件与云端文件采用完全相同的铸造逻辑。

**统一处理流程对比：**

本地文件（已实现）                    云端文档（本模块目标）

──────────────────                   ──────────────────

fsnotify 检测变更                     Drive/Dropbox API 拉取当前版本文本

       ↓                                       ↓

与 SQLite 快照对比                    与 SQLite 快照对比（虚拟路径如 gdrive://docId）

       ↓                                       ↓

本地计算 Diff Hunk                    本地计算 Diff Hunk（内容不离机）

       ↓                                       ↓

截断摘录 → AI 总结                    截断摘录 → AI 总结

       ↓                                       ↓

铸造内容型 VC 凭证                    铸造内容型 VC 凭证（与本地完全等价）

**各平台内容接入方案：**

| 平台 | 内容获取 API | 格式 |
| :---- | :---- | :---- |
| **Google Docs** | Drive API `export?format=txt` | 纯文本 |
| **Google Sheets** | Drive API `export?format=csv` | CSV |
| **Dropbox Paper** | Dropbox API `/paper/docs/download` | Markdown |
| **Notion** | Notion API `/blocks/{id}` 递归读取 | JSON→纯文本 |
| **OneDrive/Word** | Microsoft Graph `content` endpoint | 纯文本 |

**双向职能：**

- **内容接入**（核心新增）：OAuth 授权后，通过 Revisions API 拉取文档历史版本，本地计算 Diff，等价于本地文件存证  
- **凭证归档**（原有）：铸造完成后将 VC JSON/HTML 自动回传至云端指定文件夹

**隐私边界不变**：文档全文在桌面端本地完成 Diff 计算，发给 AI 的只是截断后的修改片段，OAuth 权限建议申请 read-only。

### 4.3 个人网站 / AI-Web 集成

用户配置一次 WebHook URL，此后每次铸造自动推送：

yoursite.com/.well-known/verihash-credentials.json  ← 凭证索引

yoursite.com/llms.txt                                ← AI 爬虫可读摘要

yoursite.com/credentials/\[vc-id\].json               ← 单条完整凭证

### 4.4 IPFS 永久存储

上传 VC JSON 到 IPFS，内容寻址，任何人可独立复现哈希验证。

### 4.5 Nostr 协议广播

将签名 VC 作为 Nostr Event 广播到全球中继器。

### 4.6 GitHub Gist 轻量方案

自动创建公开 Gist，零成本，天然 AI 可爬取。

---

## 🗃️ Phase 5：沉浸式账本层 (The Immutable Ledger)

**状态：✅ 已完成**

| 功能 | 状态 |
| :---- | :---- |
| 双视图标签页 WORKBENCH / THE\_LEDGER | ✅ |
| 历史凭证时间线列表 | ✅ |
| 详情抽屉（AI 摘要 \+ 文件清单） | ✅ |
| JSON Receipt 一键导出 | ✅ |
| 铸造后自动写入账本数据库 | ✅ |
| 发布信道状态追踪徽章 | 🔄 Phase 4 后实现 |

---

## 🌐 Phase 6：AI-Web 身份层 (Machine-Readable Identity)

**状态：📋 规划中**

### 6.1 可验证技能图谱

从所有历史 VC 的 `[VERIFIED SKILL TAGS]` 聚合，生成每个技能的"工时权重"与机器可读的 JSON-LD ProfilePage Schema。

### 6.2 llms.txt 自动生成

参照新兴的 llms.txt 标准，自动维护供 AI 爬虫读取的身份摘要（与 4.3 联动）。

### 6.3 链上时间戳锚点（可选）

将 VC 的 `hashChainRoot` 发布到 Arweave，实现独立于 VeriHash 本身的第三方可验证性。

---

## 🛡️ Phase 7：容灾与创世层 (Disaster Recovery & Genesis)

**状态：📋 规划中**

### 7.1 BYOS 加密冷备份

定期将 `proof_of_work.db` 用公钥加密导出为 `.vhb` 包，用户自行同步至云端。 **恢复闭环**：新设备 → 输入助记词 → 解密 .vhb → 完整恢复所有心血数据

### 7.2 Genesis ID 系统

按时间先后分配 OG 编号（`#00047`），仅记录公钥 \+ 时间戳，建立圈层认同。

---

## 🌐 Phase 8：浏览器扩展程序层 (Browser Extension Layer)

**状态：🔮 中远期 | 依赖 Phase 4.2 完成**

**架构定位修正**：浏览器扩展是 Phase 4.2 云端集成的**轻量 UI 入口**，不做任何内容处理。所有内容抓取、Diff 计算、AI 调用均由桌面端 VeriHash 完成，扩展只传递文档 ID。

### 8.0 通信架构：Localhost WebSocket（放弃 Chrome Native Messaging）

**放弃 Native Messaging 的原因**：跨平台配置矩阵复杂（Windows 注册表 / macOS 系统目录 / Linux 沙盒兼容性问题），不适合面向普通用户的开源工具。

**采用 Localhost WebSocket**：

ws://127.0.0.1:54321

- 零安装门槛，即插即用  
- 支持所有浏览器（Chrome / Firefox / Edge / Arc / Safari）  
- Linux Flatpak / Snap 环境完全兼容  
- 应用层 Token 完成安全验证，无需操作系统权限

业界成熟方案：Bitwarden、1Password、Docker Desktop 扩展均采用此架构。

### 8.1 扩展的唯一职责

用户在 Google Docs 中编辑

       ↓

扩展从 URL 中解析 Doc ID（极简逻辑）

       ↓

用户点击扩展里的 \[MINT\] 按钮

       ↓

WebSocket 发送 {platform: "google-docs", docId: "1BxiMV..."}

       ↓

桌面端 VeriHash 接管：

  → Drive API 拉取当前版本文本

  → 与 SQLite 快照对比，计算 Diff Hunk

  → 截断摘录 → AI 总结

  → 铸造内容型 VC（与本地文件完全等价）

  → 写入 SQLite 快照

**扩展代码极其简单**：不涉及内容读取，安全审计成本极低，用户信任成本低。

### 8.2 支持的平台范围

| 平台 | 扩展行为 | 桌面端通过 API 获取 |
| :---- | :---- | :---- |
| Google Docs | 解析 `/d/{docId}/` | Drive API |
| Google Sheets | 解析 `/d/{docId}/` | Drive API |
| Notion | 解析 `notion.so/{pageId}` | Notion API |
| Dropbox Paper | 解析 `paper.dropbox.com/doc/{docId}` | Dropbox API |
| OneDrive/Word | 解析文档 URL | Microsoft Graph |

---

## 📡 Phase 9：代理社交与 AI 守门人 (Agentic Network)

**状态：🔮 远期终局**

### 9.1 Nostr 双向雷达

广播 VC 到全球中继器；本地 AI 过滤噪音，将顶级同行广播推送到"发现流"。

### 9.2 AI 守门人与数字外交官

外部世界面对你的 AI Agent，而非私人联系方式。只有极高价值对话才触发人工接管。

---

## 📊 全局开发优先级矩阵

| 功能 | 用户价值 | 实现难度 | 优先级 |
| :---- | :---- | :---- | :---- |
| Phase 3.1 HTML 凭证卡片 | ⭐⭐⭐⭐⭐ | 🟢 低 | 🔥 立即 |
| **Phase 2.x 智能 Diff 提取算法** | ⭐⭐⭐⭐⭐ | 🟡 中 | 🔥 近期 |
| Phase 4.3 个人网站 WebHook | ⭐⭐⭐⭐⭐ | 🟡 中 | 🔥 近期 |
| **Phase 4.2 云端存储双向集成（内容接入）** | ⭐⭐⭐⭐⭐ | 🔴 中高 | 🌟 下一批 |
| Phase 1 云端目录智能识别 | ⭐⭐⭐⭐ | 🟢 低 | 🌟 下一批 |
| Phase 6.2 llms.txt 生成 | ⭐⭐⭐⭐ | 🟢 低 | 🌟 下一批 |
| Phase 4.4 IPFS 发布 | ⭐⭐⭐ | 🟡 中 | 📋 规划 |
| Phase 4.6 GitHub Gist | ⭐⭐⭐ | 🟢 低 | 📋 规划 |
| Phase 7.1 BYOS 加密备份 | ⭐⭐⭐⭐⭐ | 🟡 中 | 📋 规划 |
| Phase 4.5 Nostr 广播 | ⭐⭐⭐ | 🟡 中 | 📋 规划 |
| Phase 6.1 技能图谱 | ⭐⭐⭐ | 🔴 中高 | 📋 规划 |
| Phase 7.2 Genesis ID | ⭐⭐ | 🟢 低 | 📋 规划 |
| **Phase 8 浏览器扩展（依赖 4.2）** | ⭐⭐⭐⭐⭐ | 🔴 高 | 🔮 中远期 |
| Phase 6.3 链上锚点 | ⭐⭐⭐ | 🔴 高 | 🔮 远期 |
| Phase 9 AI 守门人 | ⭐⭐⭐⭐⭐ | 🔴 极高 | 🔮 远期 |

---

## 核心叙事（最终版）

**VeriHash Nexus 不对抗云端，它是云端世界的公证人。**

不管工作发生在本地文件夹、Google Drive、还是 Notion——铸造逻辑完全一致：**AI 只见修改片段，完整原文永不离机，他人无需查阅全文，即可知晓你做了哪些工作。**

在 AI 生成内容泛滥的时代，唯一有竞争力的护城河，是证明你的工作是真实的。 **护城河来自不可伪造性，而不是来自复杂度。**  
