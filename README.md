# Scopecheck

<p align="center">
  <img src="scopetest.png" alt="Scope Test Plugin" width="400"/>
</p>

A plugin that provides insight into the scope of an AgentUP Bearer token:


## Installation

### For development:
```bash
cd scopecheck
pip install -e .
```

### From AgentUp Registry or PyPi (when published):
```bash
pip install scopecheck
```

## Usage

Add the plugin to your AgentUP agent configuration:

```yaml
plugins:
  - plugin_id: scopecheck
    name: Scope Check
    description: Plugin to check scopes for API access
    input_mode: text
    output_mode: text
    routing_mode: direct
    keywords: ["scopecheck", "check", "api"]
    patterns: ['.scopecheck']  # Catch-all for minimal template
    priority: 50
    plugin_type: "local"
    required_scopes: ["api:read"]  # Example scope


Make a call using the pattern or keyword:

```bash
curl -s -X POST http://localhost:8000/ \
    -H "Authorization: Bearer <scope based token>" \
    -H "Content-Type: application/json" \
    -d '{
      "jsonrpc": "2.0",
      "method": "message/send",
      "params": {
        "message": {
          "role": "user",
          "parts": [{"kind": "text", "text": "scopecheck"}],
          "messageId": "msg-005",
          "kind": "message"
        }
      },
      "id": "req-005"
    }' | jq -r '.result.artifacts[].parts[].text'
Scope Analysis Report
=======================
Timestamp: 2025-07-15T12:08:19.268556

Summary:
- Total scopes discovered: 1
- Authentication status: Authenticated
- Context types analyzed: authentication_info, task_context, services_context, metadata_context
- Warnings: 0

Discovered Scopes:
  - `api:read`

Authentication Details:
- User ID: test-user-123
- User scopes:
  - `api:read`
- Context attributes:
  config, metadata, services, state, task
- Debug info:
  - Context auth user ID: test-user-123
  - Context auth scopes: ['api:read']
  - Context auth success: True

Task Context:
- Task ID: 26a7d594-3e4a-4d4e-9f13-6493b6faa840
- Context ID: a1618aa6-be54-4b19-b578-ffb2604e6b00
- Has history: True
- Has artifacts: False

Services Context:
- Available services: close_all, config, get_any_mcp_client, get_cache, get_database, get_llm, get_mcp_client, get_mcp_http_client, get_mcp_server, get_service, get_web_api, health_check_all, initialize_all, list_services, register_service, register_service_type
- Service count: 16

---
*This report was generated by the Scopecheck debug plugin*
```
