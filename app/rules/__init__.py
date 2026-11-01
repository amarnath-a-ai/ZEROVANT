"""Rule engine module containing all 10 security rules and the rule registry."""

from app.rules.base import BaseRule, Finding, Rule, Severity
from app.rules.r_artifact_leak import ArtifactLeakRule
from app.rules.r_deploy_environment import DeployEnvironmentRule
from app.rules.r_excessive_permissions import ExcessivePermissionsRule
from app.rules.r_long_lived_credentials import LongLivedCredentialsRule
from app.rules.r_overprovisioned_secrets import OverprovisionedSecretsRule
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

ALL_RULES = CORE_RULES + BATCH_A_RULES

for rule_cls in ALL_RULES:
    default_registry.register(rule_cls)

__all__ = [
    "ALL_RULES",
    "ArtifactLeakRule",
    "BATCH_A_RULES",
    "BaseRule",
    "CORE_RULES",
    "DeployEnvironmentRule",
    "ExcessivePermissionsRule",
    "Finding",
    "LongLivedCredentialsRule",
    "OverprovisionedSecretsRule",
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
    "default_registry",
]

