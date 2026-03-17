"""Thin CAI-facing orchestration app for cai-platform-v2."""

from cai_orchestrator.cai_terminal import (
    build_agent_from_settings,
    build_egs_analist_agent,
    build_platform_investigation_agent,
    run_cai_terminal,
    run_cai_terminal_session,
)
from cai_orchestrator.cai_tools import PlatformApiToolService, load_payload_file
from cai_orchestrator.config import (
    CaiIntegrationSettings,
    DEFAULT_CAI_AGENT_TYPE,
    DEFAULT_PLATFORM_API_BASE_URL,
    load_cai_integration_settings,
)
from cai_orchestrator.app import (
    CaiOrchestratorApp,
    build_cai_watchguard_agent,
    create_orchestrator_app,
    get_platform_api_base_url,
    main,
    run_cli,
)
from cai_orchestrator.client import PlatformApiClient
from cai_orchestrator.errors import (
    CaiOrchestratorError,
    InvalidOperatorInputError,
    MissingCaiDependencyError,
    OrchestrationFlowError,
    PlatformApiRequestError,
    PlatformApiUnavailableError,
)
from cai_orchestrator.flows import (
    PhishingEmailAssessmentRequest,
    PhishingEmailAssessmentResult,
    WatchGuardGuardedQueryRequest,
    WatchGuardInvestigationRequest,
    WatchGuardInvestigationResult,
    run_phishing_email_basic_assessment,
    run_watchguard_analytics_bundle_basic,
    run_watchguard_filter_denied_events,
    run_watchguard_guarded_custom_query,
    run_watchguard_log_investigation,
    run_watchguard_top_talkers_basic,
)

__all__ = [
    "CaiOrchestratorApp",
    "CaiOrchestratorError",
    "CaiIntegrationSettings",
    "DEFAULT_CAI_AGENT_TYPE",
    "DEFAULT_PLATFORM_API_BASE_URL",
    "InvalidOperatorInputError",
    "MissingCaiDependencyError",
    "OrchestrationFlowError",
    "PhishingEmailAssessmentRequest",
    "PhishingEmailAssessmentResult",
    "PlatformApiToolService",
    "PlatformApiClient",
    "PlatformApiRequestError",
    "PlatformApiUnavailableError",
    "WatchGuardGuardedQueryRequest",
    "WatchGuardInvestigationRequest",
    "WatchGuardInvestigationResult",
    "build_agent_from_settings",
    "build_egs_analist_agent",
    "build_cai_watchguard_agent",
    "build_platform_investigation_agent",
    "create_orchestrator_app",
    "get_platform_api_base_url",
    "load_cai_integration_settings",
    "load_payload_file",
    "main",
    "run_phishing_email_basic_assessment",
    "run_cai_terminal",
    "run_cai_terminal_session",
    "run_watchguard_analytics_bundle_basic",
    "run_watchguard_filter_denied_events",
    "run_watchguard_guarded_custom_query",
    "run_watchguard_log_investigation",
    "run_watchguard_top_talkers_basic",
    "run_cli",
]
