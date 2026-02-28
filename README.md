# VC_replan-mcp

Architecture Review MCP Server — 7 维度架构审查 + 知识库自动沉淀。

作为 Claude Code 的"冷静建筑师 + 逻辑安全网关"，在方案落地前进行多维度审查，
自动检索 Web 情报和历史 KB 记录，输出结构化漏洞报告。

## 功能概览

- **7 维度审查矩阵**：Security / Performance / Architecture / Compatibility / DataIntegrity / Reliability / Observability
- **4 级严重度**：S0 (Fatal) → S1 (Must-fix) → S2 (Warning) → S3 (Suggestion)
- **Web 情报检索**：通过 UniFuncs API 自动搜索 + 深度阅读，注入防御过滤
- **双层知识库**：`global/`（跨项目通用）+ `projects/{id}/`（项目专属），反向链接互通
- **去重机制**：vuln_id 精确匹配 + keyword overlap >70% 模糊匹配
- **Prompt 注入防御**：定界符隔离 + 12 种注入模式检测

## 项目结构

```
VC_replan-mcp/
├── server.py              # MCP 入口（FastMCP + stdio）
├── config.py              # 环境变量加载 + API Key 脱敏
├── requirements.txt       # 依赖锁定
├── models/
│   └── schemas.py         # Pydantic v2 数据模型
├── engine/
│   ├── sanitizer.py       # 注入检测 + 定界符包裹
│   ├── researcher.py      # Web 搜索 + 深度阅读
│   ├── kb_retriever.py    # KB 索引检索 + 路径安全
│   ├── kb_writer.py       # 双层写入 + 去重 + 反向链接
│   ├── prompt_builder.py  # 审查 Prompt 构建（7 维矩阵）
│   ├── reviewer.py        # OpenAI 兼容 API 调用
│   └── parser.py          # JSON 解析 + 正则兜底
├── tools/
│   ├── audit.py           # 审查流水线编排
│   └── kb_update.py       # KB 维护操作（5 种 action）
├── clink_core/            # CLI Bridge（claude/gemini/codex）
├── config/                # CLI 客户端配置 + 系统提示词
└── tests/                 # 58 个单元/集成测试
```

## 快速开始

### 1. 安装依赖

```bash
cd VC_replan-mcp
pip install -r requirements.txt
```

### 2. 配置环境变量

```bash
cp .env.example .env
# 编辑 .env 填入实际的 API Key
```

必填项：
- `REVIEWER_API_BASE` — 审查模型 API 地址（OpenAI 兼容）
- `REVIEWER_API_KEY` — 审查模型 API Key
- `REVIEWER_MODEL` — 模型名称（如 `deepseek-chat`）
- `UNIFUNCS_API_KEY` — UniFuncs Web 搜索 API Key

可选项：
- `KB_PATH` — 知识库根目录（默认 `VC_planning_mcp_kb/`）
- `KB_CLI` — KB 检索使用的 CLI（`claude` / `gemini` / `codex`，默认 `claude`）
- `KB_AUTO_WRITE` — 审查后自动写入 KB（`true` / `false`，默认 `true`）
- `KB_WRITE_S2` — S2 级别是否写入 KB（默认 `true`）

### 3. 接入 Claude Code

#### 方式一：命令行一键添加

```bash
claude mcp add vc-replan-mcp \
  -s user \
  -e REVIEWER_API_BASE=https://api.deepseek.com/v1 \
  -e REVIEWER_API_KEY=你的审查模型Key \
  -e REVIEWER_MODEL=deepseek-chat \
  -e UNIFUNCS_API_KEY=你的UniFuncs-Key \
  -e KB_PATH=/你的路径/VC_replan-mcp/VC_planning_mcp_kb \
  -e KB_AUTO_WRITE=true \
  -e KB_WRITE_S2=true \
  -- python3 "/你的路径/VC_replan-mcp/server.py"
```

#### 方式二：手动写入 claude.json

文件位置：`~/.claude/claude.json`

在 `mcpServers` 字段中添加：

```json
{
  "mcpServers": {
    "vc-replan-mcp": {
      "command": "python3",
      "args": ["/你的路径/VC_replan-mcp/server.py"],
      "env": {
        "REVIEWER_API_BASE": "https://api.deepseek.com/v1",
        "REVIEWER_API_KEY": "你的审查模型Key",
        "REVIEWER_MODEL": "deepseek-chat",
        "UNIFUNCS_API_KEY": "你的UniFuncs-Key",
        "KB_PATH": "/你的路径/VC_replan-mcp/VC_planning_mcp_kb",
        "KB_AUTO_WRITE": "true",
        "KB_WRITE_S2": "true"
      }
    }
  }
}
```

> 如果 `claude.json` 里已有其他 MCP server，把 `vc-replan-mcp` 这段加到 `mcpServers` 对象里即可，不要覆盖已有配置。

#### 方式三：uvx 方式

命令行添加：

```bash
claude mcp add vc-replan-mcp \
  -s user \
  -e REVIEWER_API_BASE=https://api.deepseek.com/v1 \
  -e REVIEWER_API_KEY=你的审查模型Key \
  -e REVIEWER_MODEL=deepseek-chat \
  -e UNIFUNCS_API_KEY=你的UniFuncs-Key \
  -e KB_PATH=/你的路径/VC_replan-mcp/VC_planning_mcp_kb \
  -e KB_AUTO_WRITE=true \
  -e KB_WRITE_S2=true \
  -- uvx --from "/你的路径/VC_replan-mcp" vc-replan-mcp
```

或手动写入 `claude.json`：

```json
{
  "mcpServers": {
    "vc-replan-mcp": {
      "command": "uvx",
      "args": ["--from", "/你的路径/VC_replan-mcp", "vc-replan-mcp"],
      "env": {
        "REVIEWER_API_BASE": "https://api.deepseek.com/v1",
        "REVIEWER_API_KEY": "你的审查模型Key",
        "REVIEWER_MODEL": "deepseek-chat",
        "UNIFUNCS_API_KEY": "你的UniFuncs-Key",
        "KB_PATH": "/你的路径/VC_replan-mcp/VC_planning_mcp_kb",
        "KB_AUTO_WRITE": "true",
        "KB_WRITE_S2": "true"
      }
    }
  }
}
```

> uvx 会自动创建隔离虚拟环境并安装依赖，无需手动 `pip install`。发布到 PyPI 后可直接 `uvx vc-replan-mcp` 运行。

#### 验证接入

添加后重启 Claude Code，输入 `/mcp` 应能看到 `vc-replan-mcp` 及其 2 个工具。

或直接调用测试：

```
请用 mcp_audit_architecture 审查一下这个方案：使用 raw SQL 拼接用户输入进行数据库查询
```

## MCP 工具

### `mcp_audit_architecture`

7 维度架构审查，完整流水线：

```
输入 → 注入过滤 → 并行(Web搜索 + KB检索) → Prompt构建 → 模型审查 → 解析 → KB写入
```

参数：
| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `proposed_solution` | string | ✅ | 待审查的技术方案 |
| `tech_stack_keywords` | string[] | ✅ | 技术栈关键词 |
| `relevant_local_context` | string | ✅ | 相关本地代码片段 |
| `project_id` | string | ❌ | 项目 ID（启用项目级 KB） |

### `mcp_kb_update`

知识库维护，支持 5 种操作：

| Action | 说明 |
|--------|------|
| `link` | 关联 global 条目到项目 |
| `unlink` | 解除关联 |
| `update_content` | 更新条目内容（关键词/技术栈） |
| `refresh_links` | 刷新所有反向链接 |
| `cleanup_stale` | 清理过期条目 |

## 知识库结构

```
KB_PATH/
├── global/
│   ├── Security/
│   │   ├── _index.yaml          # 索引（关键词/去重/命中计数）
│   │   └── 2026-02-28_V001_sql-injection.md
│   ├── Performance/
│   └── ...
└── projects/
    └── my-project/
        └── Security/
            ├── _index.yaml
            └── 2026-02-28_V001_sql-injection.md  # 含 global_ref 链接
```

## 安全设计

- **Prompt 注入防御**：12 种注入模式正则检测 + `<<<UNTRUSTED_BEGIN>>>` 定界符隔离
- **路径安全**：`Path.resolve().relative_to()` 白名单校验，防止路径穿越
- **API Key 脱敏**：日志中自动遮蔽（`sk-****xyz`）
- **事务性写入**：先写 `.md`，再更新 `_index.yaml`，失败时回滚

## 测试

```bash
python -m pytest tests/ -v
```

58 个测试覆盖：sanitizer / researcher / kb_writer / kb_update / prompt_builder / parser / 端到端集成。

## 技术栈

- Python 3.10+
- [MCP Python SDK](https://github.com/modelcontextprotocol/python-sdk) (FastMCP)
- Pydantic v2（数据校验 + JSON Schema）
- OpenAI SDK（兼容任意 OpenAI API 格式的模型）
- PyYAML（KB 索引管理）

## License

MIT
