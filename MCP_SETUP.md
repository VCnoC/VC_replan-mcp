# VC_replan-mcp — Claude Code MCP 接入指南

## 方式一：claude mcp add 命令

```bash
claude mcp add vc-replan-mcp \
  -s user \
  -e REVIEWER_API_BASE=https://api.deepseek.com/v1 \
  -e REVIEWER_API_KEY=sk-xxxxx \
  -e REVIEWER_MODEL=deepseek-chat \
  -e UNIFUNCS_API_KEY=sk-xxxxx \
  -- python server.py
```

## 方式二：手动编辑 claude_desktop_config.json

```json
{
  "mcpServers": {
    "vc-replan-mcp": {
      "command": "python",
      "args": ["D:/All_Project/Planning MCP/VC_replan-mcp/server.py"],
      "env": {
        "REVIEWER_API_BASE": "https://api.deepseek.com/v1",
        "REVIEWER_API_KEY": "sk-xxxxx",
        "REVIEWER_MODEL": "deepseek-chat",
        "UNIFUNCS_API_KEY": "sk-xxxxx",
        "KB_PATH": "VC_planning_mcp_kb/",
        "KB_CLI": "claude",
        "KB_AUTO_WRITE": "true",
        "KB_WRITE_S2": "true"
      }
    }
  }
}
```
