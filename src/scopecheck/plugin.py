"""Scopecheck plugin for AgentUp.

A debug plugin that analyzes and logs all discovered scopes from the AgentUp context.
"""

import json
import logging
from datetime import datetime
from typing import Any

import pluggy
from agent.plugins import CapabilityInfo, CapabilityContext, CapabilityResult, ValidationResult, CapabilityType

hookimpl = pluggy.HookimplMarker("agentup")
logger = logging.getLogger(__name__)


class Plugin:
    """Main plugin class for Scopecheck - analyzes and logs context scopes."""

    def __init__(self):
        """Initialize the plugin."""
        self.name = "scopecheck"
        self.scope_analysis_history = []

    @hookimpl
    def register_capability(self) -> CapabilityInfo:
        """Register the capability with AgentUp."""
        return CapabilityInfo(
            id="scopecheck",
            name="Scope Check Debug",
            version="0.1.0",
            description="Debug plugin that analyzes and logs all discovered scopes from AgentUp context",
            capabilities=[CapabilityType.TEXT],
            tags=["debug", "scope", "analysis", "logging"],
            config_schema={
                "type": "object",
                "properties": {
                    "log_level": {
                        "type": "string",
                        "enum": ["DEBUG", "INFO", "WARNING", "ERROR"],
                        "default": "INFO",
                        "description": "Logging level for scope analysis"
                    },
                    "include_sensitive": {
                        "type": "boolean",
                        "default": False,
                        "description": "Whether to include potentially sensitive scope information"
                    },
                    "detailed_analysis": {
                        "type": "boolean",
                        "default": True,
                        "description": "Whether to perform detailed scope analysis"
                    }
                }
            }
        )

    @hookimpl
    def validate_config(self, config: dict) -> ValidationResult:
        """Validate capability configuration."""
        errors = []
        warnings = []

        # Validate log level
        log_level = config.get("log_level", "INFO")
        if log_level not in ["DEBUG", "INFO", "WARNING", "ERROR"]:
            errors.append("Invalid log_level. Must be one of: DEBUG, INFO, WARNING, ERROR")

        # Validate boolean fields
        for field in ["include_sensitive", "detailed_analysis"]:
            value = config.get(field)
            if value is not None and not isinstance(value, bool):
                errors.append(f"{field} must be a boolean value")

        if config.get("include_sensitive", False):
            warnings.append("include_sensitive is enabled - be careful with sensitive data logging")

        return ValidationResult(
            valid=len(errors) == 0,
            errors=errors,
            warnings=warnings
        )

    @hookimpl
    def can_handle_task(self, context: CapabilityContext) -> float:
        """Check if this capability can handle the task."""
        user_input = self._extract_user_input(context).lower()

        # High confidence for explicit scope check requests
        scope_keywords = {
            "scope check": 1.0,
            "scopecheck": 1.0,
            "analyze scopes": 1.0,
            "debug scopes": 1.0,
            "show scopes": 0.9,
            "list scopes": 0.9,
            "context scopes": 0.8,
            "permissions": 0.7,
            "auth scopes": 0.8,
            "debug context": 0.6,
            "context analysis": 0.6
        }

        confidence = 0.0
        for keyword, score in scope_keywords.items():
            if keyword in user_input:
                confidence = max(confidence, score)

        return confidence

    @hookimpl
    def execute_capability(self, context: CapabilityContext) -> CapabilityResult:
        """Execute the scope analysis capability."""
        try:
            # Get configuration
            config = context.config or {}
            log_level = config.get("log_level", "INFO")
            include_sensitive = config.get("include_sensitive", False)
            detailed_analysis = config.get("detailed_analysis", True)

            # Set logger level
            logger.setLevel(getattr(logging, log_level))

            # Perform scope analysis
            scope_analysis = self._analyze_context_scopes(context, include_sensitive, detailed_analysis)

            # Log the analysis
            self._log_scope_analysis(scope_analysis, log_level)

            # Store in history
            self.scope_analysis_history.append({
                "timestamp": datetime.now().isoformat(),
                "analysis": scope_analysis
            })

            # Generate user-friendly response
            response = self._generate_scope_report(scope_analysis, detailed_analysis)

            return CapabilityResult(
                content=response,
                success=True,
                metadata={
                    "capability": "scopecheck",
                    "analysis_timestamp": datetime.now().isoformat(),
                    "scopes_discovered": len(scope_analysis.get("discovered_scopes", [])),
                    "context_analyzed": True
                }
            )

        except Exception as e:
            logger.error(f"Error during scope analysis: {str(e)}", exc_info=True)
            return CapabilityResult(
                content=f"Error analyzing scopes: {str(e)}",
                success=False,
                error=str(e),
                metadata={"capability": "scopecheck", "error": True}
            )

    def _analyze_context_scopes(self, context: CapabilityContext, include_sensitive: bool, detailed: bool) -> dict[str, Any]:
        """Analyze the context to discover all available scopes."""
        analysis = {
            "timestamp": datetime.now().isoformat(),
            "discovered_scopes": [],
            "authentication_info": {},
            "task_context": {},
            "configuration_scopes": {},
            "services_context": {},
            "state_context": {},
            "metadata_context": {},
            "scope_hierarchy": {},
            "warnings": []
        }

        # Analyze authentication and user scopes
        try:
            # Get all available context attributes for debugging
            context_attributes = [attr for attr in dir(context) if not attr.startswith('_')]
            
            # Try multiple ways to get authentication info
            auth_info = {}
            
            # Method 1: Direct attribute access
            user_id = getattr(context, 'user_id', None)
            user_scopes = getattr(context, 'user_scopes', set())
            auth_metadata = getattr(context, 'auth_metadata', {})
            
            # Method 2: Check for auth_result object
            auth_result = getattr(context, 'auth_result', None)
            
            # Method 3: Try different ways to access authentication
            # Check if we have a request object in context
            request = getattr(context, 'request', None)
            
            # Method 3a: Try security context functions
            try:
                from agent.security.context import get_current_auth
                current_auth = get_current_auth()
                
                if current_auth:
                    auth_info["context_auth"] = {
                        "current_auth": str(current_auth),
                        "auth_success": getattr(current_auth, 'success', False),
                        "auth_user_id": getattr(current_auth, 'user_id', None),
                        "auth_scopes": list(getattr(current_auth, 'scopes', set())),
                        "auth_metadata": getattr(current_auth, 'metadata', {})
                    }
                    
                    # Use context auth if local context doesn't have info
                    if not user_id and current_auth.user_id:
                        user_id = current_auth.user_id
                    if not user_scopes and current_auth.scopes:
                        user_scopes = current_auth.scopes
                    if not auth_metadata and current_auth.metadata:
                        auth_metadata = current_auth.metadata
                        
            except Exception as context_auth_error:
                auth_info["context_auth_error"] = str(context_auth_error)
            
            # Method 3b: Try security functions with request parameter
            if request:
                try:
                    from agent.security import get_current_user_id, get_current_scopes
                    request_user_id = get_current_user_id(request)
                    request_scopes = get_current_scopes(request)
                    
                    auth_info["request_auth"] = {
                        "user_id": request_user_id,
                        "scopes": list(request_scopes) if request_scopes else []
                    }
                    
                    if not user_id and request_user_id:
                        user_id = request_user_id
                    if not user_scopes and request_scopes:
                        user_scopes = request_scopes
                        
                except Exception as request_auth_error:
                    auth_info["request_auth_error"] = str(request_auth_error)
            
            # Method 4: Check auth_result attributes
            if auth_result:
                auth_info["auth_result"] = {
                    "type": type(auth_result).__name__,
                    "success": getattr(auth_result, 'success', None),
                    "user_id": getattr(auth_result, 'user_id', None),
                    "scopes": list(getattr(auth_result, 'scopes', set())),
                    "metadata": getattr(auth_result, 'metadata', {}),
                    "attributes": [attr for attr in dir(auth_result) if not attr.startswith('_')]
                }
                
                if not user_id:
                    user_id = getattr(auth_result, 'user_id', None)
                if not user_scopes:
                    user_scopes = getattr(auth_result, 'scopes', set())
                if not auth_metadata:
                    auth_metadata = getattr(auth_result, 'metadata', {})
            
            # Method 5: Try to access task-level auth info
            task_auth_info = {}
            if hasattr(context, 'task'):
                task = context.task
                if hasattr(task, 'metadata') and task.metadata:
                    task_auth_info["task_metadata"] = task.metadata
                    
                if hasattr(task, 'history') and task.history:
                    # Look for auth info in message history
                    for msg in task.history:
                        if hasattr(msg, 'metadata') and msg.metadata:
                            task_auth_info["message_metadata"] = msg.metadata
                            break
            
            # Determine authentication status
            is_authenticated = bool(user_id or user_scopes or 
                                  (auth_result and getattr(auth_result, 'success', False)))
            
            # Convert scopes to list for JSON serialization
            user_scopes_list = list(user_scopes) if isinstance(user_scopes, set) else user_scopes or []
            
            analysis["authentication_info"] = {
                "is_authenticated": is_authenticated,
                "user_id": user_id,
                "user_scopes": user_scopes_list,
                "auth_metadata": auth_metadata,
                "context_attributes": context_attributes,
                "debug_info": auth_info,
                "task_auth_info": task_auth_info
            }
            
            # Add discovered scopes from authentication
            if user_scopes_list:
                analysis["discovered_scopes"].extend(user_scopes_list)
                
        except Exception as e:
            analysis["warnings"].append(f"Could not analyze authentication: {str(e)}")

        # Analyze task context
        if hasattr(context, 'task') and context.task:
            try:
                task_info = self._analyze_task_context(context.task, include_sensitive)
                analysis["task_context"] = task_info
            except Exception as e:
                analysis["warnings"].append(f"Could not analyze task context: {str(e)}")

        # Analyze configuration context
        if hasattr(context, 'config') and context.config:
            try:
                config_info = self._analyze_config_context(context.config, include_sensitive)
                analysis["configuration_scopes"] = config_info
            except Exception as e:
                analysis["warnings"].append(f"Could not analyze configuration context: {str(e)}")

        # Analyze services context
        if hasattr(context, 'services') and context.services:
            try:
                services_info = self._analyze_services_context(context.services, include_sensitive)
                analysis["services_context"] = services_info
            except Exception as e:
                analysis["warnings"].append(f"Could not analyze services context: {str(e)}")

        # Analyze state context
        if hasattr(context, 'state') and context.state:
            try:
                state_info = self._analyze_state_context(context.state, include_sensitive)
                analysis["state_context"] = state_info
            except Exception as e:
                analysis["warnings"].append(f"Could not analyze state context: {str(e)}")

        # Analyze metadata context
        if hasattr(context, 'metadata') and context.metadata:
            try:
                metadata_info = self._analyze_metadata_context(context.metadata, include_sensitive)
                analysis["metadata_context"] = metadata_info
            except Exception as e:
                analysis["warnings"].append(f"Could not analyze metadata context: {str(e)}")

        # Remove duplicates from discovered scopes
        analysis["discovered_scopes"] = list(set(analysis["discovered_scopes"]))

        # Add scope analysis summary
        analysis["summary"] = {
            "total_scopes_discovered": len(analysis["discovered_scopes"]),
            "authenticated": analysis["authentication_info"].get("is_authenticated", False),
            "context_types_analyzed": [
                key for key in ["authentication_info", "task_context", "configuration_scopes",
                               "services_context", "state_context", "metadata_context"]
                if analysis[key]
            ],
            "warnings_count": len(analysis["warnings"])
        }

        return analysis

    def _analyze_task_context(self, task: Any, include_sensitive: bool) -> dict[str, Any]:
        """Analyze task context for scope information."""
        task_info = {
            "task_id": getattr(task, 'id', None),
            "context_id": getattr(task, 'contextId', None),
            "kind": getattr(task, 'kind', None),
            "has_history": bool(getattr(task, 'history', None)),
            "has_artifacts": bool(getattr(task, 'artifacts', None)),
            "has_metadata": bool(getattr(task, 'metadata', None))
        }

        # Analyze task metadata for scope hints
        if hasattr(task, 'metadata') and task.metadata:
            metadata_scopes = self._extract_scopes_from_metadata(task.metadata)
            task_info["metadata_scopes"] = metadata_scopes

        # Analyze message history
        if hasattr(task, 'history') and task.history:
            history_info = self._analyze_message_history(task.history, include_sensitive)
            task_info["history_analysis"] = history_info

        return task_info

    def _analyze_config_context(self, config: dict[str, Any], include_sensitive: bool) -> dict[str, Any]:
        """Analyze configuration context for scope information."""
        config_info = {
            "config_keys": list(config.keys()) if include_sensitive else ["<redacted>" if k.lower() in ['password', 'secret', 'key', 'token'] else k for k in config.keys()],
            "has_auth_config": any(key in config for key in ['auth', 'authentication', 'security']),
            "has_scope_config": any(key in config for key in ['scope', 'scopes', 'permissions']),
            "discovered_scopes": []
        }

        # Look for scope-related configuration
        scope_keys = ['scope', 'scopes', 'permissions', 'auth', 'security']
        for key in scope_keys:
            if key in config:
                scope_data = config[key]
                extracted_scopes = self._extract_scopes_from_data(scope_data)
                config_info["discovered_scopes"].extend(extracted_scopes)

        return config_info

    def _analyze_services_context(self, services: Any, include_sensitive: bool) -> dict[str, Any]:
        """Analyze services context for scope information."""
        services_info = {
            "available_services": [],
            "service_count": 0,
            "service_types": {},
            "service_registry_type": type(services).__name__
        }

        try:
            # Handle different types of service objects
            if hasattr(services, 'keys') and callable(services.keys):
                # dictionary-like services
                services_info["available_services"] = list(services.keys())
                services_info["service_count"] = len(services)

                # Analyze each service
                for service_name, service_obj in services.items():
                    service_type = type(service_obj).__name__
                    services_info["service_types"][service_name] = service_type

                    # Look for scope-related methods or attributes
                    if hasattr(service_obj, 'scopes') or hasattr(service_obj, 'permissions'):
                        services_info[f"{service_name}_scopes"] = "<service has scope attributes>"

            elif hasattr(services, '__dict__'):
                # Object with attributes
                service_attrs = [attr for attr in dir(services) if not attr.startswith('_')]
                services_info["available_services"] = service_attrs
                services_info["service_count"] = len(service_attrs)

                for attr_name in service_attrs:
                    try:
                        attr_obj = getattr(services, attr_name)
                        if not callable(attr_obj):  # Skip methods
                            service_type = type(attr_obj).__name__
                            services_info["service_types"][attr_name] = service_type

                            # Look for scope-related methods or attributes
                            if hasattr(attr_obj, 'scopes') or hasattr(attr_obj, 'permissions'):
                                services_info[f"{attr_name}_scopes"] = "<service has scope attributes>"
                    except Exception as e:
                        services_info["service_types"][attr_name] = f"<error accessing: {str(e)}>"

            elif hasattr(services, 'get_services'):
                # Service registry with get_services method
                try:
                    service_list = services.get_services()
                    services_info["available_services"] = [str(s) for s in service_list]
                    services_info["service_count"] = len(service_list)
                except Exception as e:
                    services_info["analysis_error"] = f"Could not call get_services(): {str(e)}"

            else:
                # Unknown service type - try to get basic info
                services_info["analysis_error"] = f"Unknown service type: {type(services).__name__}"
                services_info["service_methods"] = [method for method in dir(services) if not method.startswith('_')]

        except Exception as e:
            services_info["analysis_error"] = f"Error analyzing services: {str(e)}"

        return services_info

    def _analyze_state_context(self, state: dict[str, Any], include_sensitive: bool) -> dict[str, Any]:
        """Analyze state context for scope information."""
        state_info = {
            "state_keys": list(state.keys()) if include_sensitive else ["<redacted>" if 'secret' in k.lower() or 'password' in k.lower() else k for k in state.keys()],
            "state_size": len(state),
            "has_auth_state": any(key in state for key in ['auth', 'authentication', 'user']),
            "discovered_scopes": []
        }

        # Look for scope-related state
        scope_keys = ['scope', 'scopes', 'permissions', 'auth', 'user']
        for key in scope_keys:
            if key in state:
                scope_data = state[key]
                extracted_scopes = self._extract_scopes_from_data(scope_data)
                state_info["discovered_scopes"].extend(extracted_scopes)

        return state_info

    def _analyze_metadata_context(self, metadata: dict[str, Any], include_sensitive: bool) -> dict[str, Any]:
        """Analyze metadata context for scope information."""
        metadata_info = {
            "metadata_keys": list(metadata.keys()),
            "metadata_size": len(metadata),
            "discovered_scopes": []
        }

        # Extract scopes from metadata
        extracted_scopes = self._extract_scopes_from_metadata(metadata)
        metadata_info["discovered_scopes"].extend(extracted_scopes)

        return metadata_info

    def _analyze_message_history(self, history: list[Any], include_sensitive: bool) -> dict[str, Any]:
        """Analyze message history for scope information."""
        history_info = {
            "message_count": len(history),
            "roles": [],
            "has_auth_messages": False,
            "discovered_scopes": []
        }

        for message in history:
            # Analyze message role
            if hasattr(message, 'role'):
                role = getattr(message, 'role')
                if role not in history_info["roles"]:
                    history_info["roles"].append(role)

            # Analyze message metadata
            if hasattr(message, 'metadata') and message.metadata:
                extracted_scopes = self._extract_scopes_from_metadata(message.metadata)
                history_info["discovered_scopes"].extend(extracted_scopes)

            # Look for auth-related content
            if hasattr(message, 'parts') and message.parts:
                for part in message.parts:
                    if hasattr(part, 'text') and part.text:
                        text = part.text.lower()
                        if any(auth_word in text for auth_word in ['auth', 'login', 'permission', 'scope']):
                            history_info["has_auth_messages"] = True

        return history_info

    def _extract_scopes_from_metadata(self, metadata: dict[str, Any]) -> list[str]:
        """Extract scope information from metadata."""
        scopes = []

        # Common scope keys
        scope_keys = ['scope', 'scopes', 'permissions', 'auth', 'authorization']

        for key, value in metadata.items():
            if key.lower() in scope_keys:
                extracted = self._extract_scopes_from_data(value)
                scopes.extend(extracted)
            elif 'scope' in key.lower():
                extracted = self._extract_scopes_from_data(value)
                scopes.extend(extracted)

        return scopes

    def _extract_scopes_from_data(self, data: Any) -> list[str]:
        """Extract scope strings from various data types."""
        scopes = []

        if isinstance(data, str):
            # Single scope string
            scopes.append(data)
        elif isinstance(data, list):
            # list of scopes
            for item in data:
                if isinstance(item, str):
                    scopes.append(item)
                elif isinstance(item, dict) and 'scope' in item:
                    scopes.append(item['scope'])
        elif isinstance(data, dict):
            # dictionary containing scope information
            for key, value in data.items():
                if 'scope' in key.lower() and isinstance(value, str):
                    scopes.append(value)
                elif isinstance(value, list):
                    scopes.extend(self._extract_scopes_from_data(value))
        elif isinstance(data, set):
            # Set of scopes
            scopes.extend(list(data))

        return scopes

    def _log_scope_analysis(self, analysis: dict[str, Any], log_level: str) -> None:
        """Log the scope analysis results."""
        log_func = getattr(logger, log_level.lower())

        log_func("=== SCOPE ANALYSIS REPORT ===")
        log_func(f"Analysis timestamp: {analysis['timestamp']}")
        log_func(f"Total scopes discovered: {len(analysis['discovered_scopes'])}")

        if analysis['discovered_scopes']:
            log_func("Discovered scopes:")
            for scope in sorted(analysis['discovered_scopes']):
                log_func(f"  - {scope}")

        # Log authentication info
        auth_info = analysis.get('authentication_info', {})
        if auth_info:
            log_func("Authentication info:")
            log_func(f"  - Authenticated: {auth_info.get('is_authenticated', False)}")
            log_func(f"  - User ID: {auth_info.get('user_id', 'N/A')}")
            log_func(f"  - User scopes: {auth_info.get('user_scopes', [])}")

        # Log warnings
        if analysis.get('warnings'):
            log_func("Warnings:")
            for warning in analysis['warnings']:
                log_func(f"  - {warning}")

        # Log detailed analysis
        if log_level == 'DEBUG':
            log_func("Full analysis:")
            log_func(json.dumps(analysis, indent=2, default=str))

        log_func("=== END SCOPE ANALYSIS ===")

    def _generate_scope_report(self, analysis: dict[str, Any], detailed: bool) -> str:
        """Generate a user-friendly scope report."""
        report = []
        report.append("Scope Analysis Report")
        report.append("=======================")
        report.append(f"Timestamp: {analysis['timestamp']}")
        report.append("")

        # Summary section
        summary = analysis.get('summary', {})
        report.append("Summary:")
        report.append(f"- Total scopes discovered: {summary.get('total_scopes_discovered', 0)}")
        report.append(f"- Authentication status: {'Authenticated' if summary.get('authenticated') else 'Not authenticated'}")
        report.append(f"- Context types analyzed: {', '.join(summary.get('context_types_analyzed', []))}")
        report.append(f"- Warnings: {summary.get('warnings_count', 0)}")
        report.append("")

        # Discovered scopes
        discovered_scopes = analysis.get('discovered_scopes', [])
        if discovered_scopes:
            report.append("Discovered Scopes:")
            for scope in sorted(discovered_scopes):
                report.append(f"  - `{scope}`")
            report.append("")

        # Authentication details
        auth_info = analysis.get('authentication_info', {})
        if auth_info:
            report.append("Authentication Details:")
            report.append(f"- User ID: {auth_info.get('user_id', 'N/A')}")
            user_scopes = auth_info.get('user_scopes', [])
            if user_scopes:
                report.append("- User scopes:")
                for scope in sorted(user_scopes):
                    report.append(f"  - `{scope}`")
            
            # Show context attributes for debugging
            context_attrs = auth_info.get('context_attributes', [])
            if context_attrs:
                report.append("- Context attributes:")
                report.append(f"  {', '.join(context_attrs)}")
            
            # Show debug info
            debug_info = auth_info.get('debug_info', {})
            if debug_info:
                report.append("- Debug info:")
                if 'context_auth' in debug_info:
                    context_auth = debug_info['context_auth']
                    report.append(f"  - Context auth user ID: {context_auth.get('auth_user_id', 'N/A')}")
                    report.append(f"  - Context auth scopes: {context_auth.get('auth_scopes', [])}")
                    report.append(f"  - Context auth success: {context_auth.get('auth_success', False)}")
                if 'context_auth_error' in debug_info:
                    report.append(f"  - Context auth error: {debug_info['context_auth_error']}")
                if 'request_auth' in debug_info:
                    request_auth = debug_info['request_auth']
                    report.append(f"  - Request auth user ID: {request_auth.get('user_id', 'N/A')}")
                    report.append(f"  - Request auth scopes: {request_auth.get('scopes', [])}")
                if 'request_auth_error' in debug_info:
                    report.append(f"  - Request auth error: {debug_info['request_auth_error']}")
                if 'auth_result' in debug_info:
                    auth_result = debug_info['auth_result']
                    report.append(f"  - Auth result type: {auth_result.get('type', 'N/A')}")
                    report.append(f"  - Auth result success: {auth_result.get('success', False)}")
                    report.append(f"  - Auth result user_id: {auth_result.get('user_id', 'N/A')}")
                    report.append(f"  - Auth result scopes: {auth_result.get('scopes', [])}")
            
            report.append("")

        # Context analysis (if detailed)
        if detailed:
            # Task context
            task_context = analysis.get('task_context', {})
            if task_context:
                report.append("Task Context:")
                report.append(f"- Task ID: {task_context.get('task_id', 'N/A')}")
                report.append(f"- Context ID: {task_context.get('context_id', 'N/A')}")
                report.append(f"- Has history: {task_context.get('has_history', False)}")
                report.append(f"- Has artifacts: {task_context.get('has_artifacts', False)}")
                report.append("")

            # Services context
            services_context = analysis.get('services_context', {})
            if services_context:
                report.append("Services Context:")
                services = services_context.get('available_services', [])
                if services:
                    report.append(f"- Available services: {', '.join(services)}")
                report.append(f"- Service count: {services_context.get('service_count', 0)}")
                report.append("")

        # Warnings
        warnings = analysis.get('warnings', [])
        if warnings:
            report.append("Warnings:")
            for warning in warnings:
                report.append(f"  - {warning}")
            report.append("")

        # Footer
        report.append("---")
        report.append("*This report was generated by the Scopecheck debug plugin*")

        return "\n".join(report)

    def _extract_user_input(self, context: CapabilityContext) -> str:
        """Extract user input from the task context."""
        if hasattr(context, 'task') and context.task:
            if hasattr(context.task, "history") and context.task.history:
                last_msg = context.task.history[-1]
                if hasattr(last_msg, "parts") and last_msg.parts:
                    part = last_msg.parts[0]
                    if hasattr(part, "text") and part.text:
                        return part.text
        return ""
