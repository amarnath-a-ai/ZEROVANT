"""Rule engine module containing all 10 security rules and the rule registry."""

from app.rules.base import BaseRule, Finding, Rule, Severity
from app.rules.r_artifact_leak import ArtifactLeakRule
from app.rules.r_bot_actor_spoofing import BotActorSpoofingRule
from app.rules.r_cache_poisoning_risk import CachePoisoningRiskRule
from app.rules.r_comment_trigger_no_auth import CommentTriggerNoAuthRule
from app.rules.r_continue_on_error_security_step import ContinueOnErrorSecurityStepRule
from app.rules.r_curl_pipe_shell import CurlPipeShellRule
from app.rules.r_deploy_environment import DeployEnvironmentRule
from app.rules.r_dispatch_input_injection import DispatchInputInjectionRule
from app.rules.r_excessive_permissions import ExcessivePermissionsRule
from app.rules.r_github_env_injection import GitHubEnvInjectionRule
from app.rules.r_insecure_commands_enabled import InsecureCommandsEnabledRule
from app.rules.r_known_vulnerable_action import KnownVulnerableActionRule
from app.rules.r_long_lived_credentials import LongLivedCredentialsRule
from app.rules.r_missing_timeout import MissingTimeoutRule
from app.rules.r_oidc_write_untrusted import OidcWriteUntrustedRule
from app.rules.r_overprovisioned_secrets import OverprovisionedSecretsRule
from app.rules.r_permissions_overbroad_job import PermissionsOverbroadJobRule
from app.rules.r_persist_credentials import PersistCredentialsRule
from app.rules.r_plaintext_secret import PlaintextSecretRule
from app.rules.r_pr_target_checkout import PrTargetCheckoutRule
from app.rules.r_script_injection import ScriptInjectionRule
from app.rules.r_secret_in_log import SecretInLogRule
from app.rules.r_secret_to_unpinned_action import SecretToUnpinnedActionRule
from app.rules.r_secrets_inherit import SecretsInheritRule
from app.rules.r_self_hosted_runner import SelfHostedRunnerRule
from app.rules.r_third_party_action import ThirdPartyActionRule
from app.rules.r_unpinned_action import UnpinnedActionRule
from app.rules.r_unpinned_docker_image import UnpinnedDockerImageRule
from app.rules.r_unpinned_reusable_workflow import UnpinnedReusableWorkflowRule
from app.rules.r_workflow_run_untrusted_artifact import WorkflowRunUntrustedArtifactRule
from app.rules.registry import RuleRegistry, default_registry

CORE_RULES = [
    UnpinnedActionRule,
    ExcessivePermissionsRule,
    PrTargetCheckoutRule,
    ScriptInjectionRule,
    PlaintextSecretRule,
    SecretInLogRule,
    LongLivedCredentialsRule,
    DeployEnvironmentRule,
    SelfHostedRunnerRule,
    ThirdPartyActionRule,
]

BATCH_A_RULES = [
    PersistCredentialsRule,
    SecretToUnpinnedActionRule,
    OverprovisionedSecretsRule,
    ArtifactLeakRule,
    SecretsInheritRule,
]

BATCH_B_RULES = [
    GitHubEnvInjectionRule,
    WorkflowRunUntrustedArtifactRule,
    CommentTriggerNoAuthRule,
    DispatchInputInjectionRule,
    BotActorSpoofingRule,
]

BATCH_C_RULES = [
    UnpinnedReusableWorkflowRule,
    UnpinnedDockerImageRule,
    CurlPipeShellRule,
    InsecureCommandsEnabledRule,
    CachePoisoningRiskRule,
]

BATCH_D_RULES = [
    OidcWriteUntrustedRule,
    PermissionsOverbroadJobRule,
    ContinueOnErrorSecurityStepRule,
    MissingTimeoutRule,
    KnownVulnerableActionRule,
]

ALL_RULES = CORE_RULES + BATCH_A_RULES + BATCH_B_RULES + BATCH_C_RULES + BATCH_D_RULES

for rule_cls in ALL_RULES:
    default_registry.register(rule_cls)

__all__ = [
    "ALL_RULES",
    "ArtifactLeakRule",
    "BATCH_A_RULES",
    "BATCH_B_RULES",
    "BATCH_C_RULES",
    "BATCH_D_RULES",
    "BaseRule",
    "BotActorSpoofingRule",
    "CachePoisoningRiskRule",
    "CommentTriggerNoAuthRule",
    "ContinueOnErrorSecurityStepRule",
    "CORE_RULES",
    "CurlPipeShellRule",
    "DeployEnvironmentRule",
    "DispatchInputInjectionRule",
    "ExcessivePermissionsRule",
    "Finding",
    "GitHubEnvInjectionRule",
    "InsecureCommandsEnabledRule",
    "KnownVulnerableActionRule",
    "LongLivedCredentialsRule",
    "MissingTimeoutRule",
    "OidcWriteUntrustedRule",
    "OverprovisionedSecretsRule",
    "PermissionsOverbroadJobRule",
    "PersistCredentialsRule",
    "PlaintextSecretRule",
    "PrTargetCheckoutRule",
    "Rule",
    "RuleRegistry",
    "ScriptInjectionRule",
    "SecretInLogRule",
    "SecretToUnpinnedActionRule",
    "SecretsInheritRule",
    "SelfHostedRunnerRule",
    "Severity",
    "ThirdPartyActionRule",
    "UnpinnedActionRule",
    "UnpinnedDockerImageRule",
    "UnpinnedReusableWorkflowRule",
    "WorkflowRunUntrustedArtifactRule",
    "default_registry",
]

