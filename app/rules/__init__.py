"""Rule engine module containing all 10 security rules and the rule registry."""

from app.rules.base import BaseRule, Finding, Severity
from app.rules.r_deploy_environment import DeployEnvironmentRule
from app.rules.r_excessive_permissions import ExcessivePermissionsRule
from app.rules.r_long_lived_credentials import LongLivedCredentialsRule
from app.rules.r_plaintext_secret import PlaintextSecretRule
from app.rules.r_pr_target_checkout import PrTargetCheckoutRule
from app.rules.r_script_injection import ScriptInjectionRule
from app.rules.r_secret_in_log import SecretInLogRule
from app.rules.r_self_hosted_runner import SelfHostedRunnerRule
from app.rules.r_third_party_action import ThirdPartyActionRule
from app.rules.r_unpinned_action import UnpinnedActionRule
from app.rules.registry import RuleRegistry, default_registry

ALL_RULES = [
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

for rule_cls in ALL_RULES:
    default_registry.register(rule_cls)

__all__ = [
    "ALL_RULES",
    "BaseRule",
    "DeployEnvironmentRule",
    "ExcessivePermissionsRule",
    "Finding",
    "LongLivedCredentialsRule",
    "PlaintextSecretRule",
    "PrTargetCheckoutRule",
    "RuleRegistry",
    "ScriptInjectionRule",
    "SecretInLogRule",
    "SelfHostedRunnerRule",
    "Severity",
    "ThirdPartyActionRule",
    "UnpinnedActionRule",
    "default_registry",
]

