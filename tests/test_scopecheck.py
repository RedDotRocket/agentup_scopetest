"""Tests for Scopecheck plugin."""

import pytest
from agent.plugins.models import CapabilityContext, CapabilityInfo
from scopecheck.plugin import Plugin


def test_plugin_registration():
    """Test that the plugin registers correctly."""
    plugin = Plugin()
    capability_info = plugin.register_capability()

    assert isinstance(capability_info, CapabilityInfo)
    assert capability_info.id == "scopecheck"
    assert capability_info.name == "Scopecheck"


def test_plugin_execution():
    """Test basic plugin execution."""
    plugin = Plugin()

    # Create a mock context
    from unittest.mock import Mock
    task = Mock()
    context = CapabilityContext(task=task)

    result = plugin.execute_capability(context)

    assert result.success
    assert result.content