"""
Scopecheck plugin for AgentUp.

A plugin that provides Scopecheck functionality
"""

import pluggy
from agent.plugins import CapabilityInfo, CapabilityContext, CapabilityResult, ValidationResult, CapabilityType
hookimpl = pluggy.HookimplMarker("agentup")


class Plugin:
    """Main plugin class for Scopecheck."""

    def __init__(self):
        """Initialize the plugin."""
        self.name = "scopecheck"

    @hookimpl
    def register_capability(self) -> CapabilityInfo:
        """Register the capability with AgentUp."""
        return CapabilityInfo(
            id="scopecheck",
            name="Scopecheck",
            version="0.1.0",
            description="A plugin that provides Scopecheck functionality",
            capabilities=[CapabilityType.TEXT],
            tags=["scopecheck", "custom"]        )

    @hookimpl
    def validate_config(self, config: dict) -> ValidationResult:
        """Validate capability configuration."""
# Add your validation logic here
        return ValidationResult(valid=True)

    @hookimpl
    def can_handle_task(self, context: CapabilityContext) -> bool:
        """Check if this capability can handle the task."""
# Add your routing logic here
        # For now, return True to handle all tasks
        return True

    @hookimpl
    def execute_capability(self, context: CapabilityContext) -> CapabilityResult:
        """Execute the capability logic."""
# Extract user input from the task
        user_input = self._extract_user_input(context)

        # Your capability logic here
        response = f"Processed by Scopecheck: {user_input}"

        return CapabilityResult(
            content=response,
            success=True,
            metadata={"capability": "scopecheck"},
        )

    def _extract_user_input(self, context: CapabilityContext) -> str:
        """Extract user input from the task context."""
        if hasattr(context.task, "history") and context.task.history:
            last_msg = context.task.history[-1]
            if hasattr(last_msg, "parts") and last_msg.parts:
                return last_msg.parts[0].text if hasattr(last_msg.parts[0], "text") else ""
        return ""