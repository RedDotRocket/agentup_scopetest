# Scopecheck

A plugin that provides Scopecheck functionality

## Installation

### For development:
```bash
cd scopecheck
pip install -e .
```

### From PyPI (when published):
```bash
pip install scopecheck
```

## Usage

This plugin provides the `scopecheck` capability to AgentUp agents.

## Development

1. Edit `src/scopecheck/plugin.py` to implement your capability logic
2. Test locally with an AgentUp agent
3. Publish to PyPI when ready

## Configuration

The capability can be configured in `agent_config.yaml`:

```yaml
plugins:
  - plugin_id: scopecheck
    config:
      # Add your configuration options here
```