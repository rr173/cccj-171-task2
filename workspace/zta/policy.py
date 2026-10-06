"""Versioned zero-trust policy model.

A policy is an immutable JSON document with a monotonically increasing integer
version.  Three concerns live in a policy:

1. Role-based allow rules (resource/action globs) plus a default-deny verdict.
2. Context constraints (minimum device attestation level, allowed countries).
3. Signal rules that map risk signals to one of four *convergent* effects:

   - ``terminate``    close the session immediately (terminal state)
   - ``revoke``       add entries to the session's grow-only revocation set
   - ``reauth``       open a gate that only a fresher re-authentication clears
   - ``attestation``  open a gate that only a fresher device attestation clears

A signal can therefore only ever shrink authorisation, demand proof, or kill the
session -- it can never grant or widen access.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass
from typing import Any, Optional

TERMINATE = "terminate"
REVOKE = "revoke"
REAUTH = "reauth"
ATTESTATION = "attestation"
SIGNAL_ACTIONS = (TERMINATE, REVOKE, REAUTH, ATTESTATION)


class PolicyError(ValueError):
    pass


@dataclass(frozen=True)
class Policy:
    version: int
    body: dict[str, Any]

    # ----- construction / validation --------------------------------------

    @classmethod
    def from_dict(cls, body: dict[str, Any]) -> "Policy":
        if not isinstance(body, dict):
            raise PolicyError("policy must be an object")
        version = body.get("version")
        if not isinstance(version, int) or version < 1:
            raise PolicyError("policy.version must be a positive integer")
        for i, rule in enumerate(body.get("rules", [])):
            for key in ("roles", "resources", "actions", "effect"):
                if key not in rule:
                    raise PolicyError(f"rules[{i}] missing {key!r}")
            if rule["effect"] not in ("allow", "deny"):
                raise PolicyError(f"rules[{i}].effect must be allow|deny")
            for key in ("roles", "resources", "actions"):
                if not isinstance(rule[key], list) or not rule[key]:
                    raise PolicyError(f"rules[{i}].{key} must be a non-empty list")
        constraints = body.get("constraints", {}) or {}
        if "device_min_level" in constraints and not isinstance(
            constraints["device_min_level"], int
        ):
            raise PolicyError("constraints.device_min_level must be an integer")
        countries = constraints.get("network_countries")
        if countries is not None and not isinstance(countries, list):
            raise PolicyError("constraints.network_countries must be a list")
        for i, sr in enumerate(body.get("signal_rules", [])):
            if not sr.get("signal"):
                raise PolicyError(f"signal_rules[{i}] missing 'signal'")
            if sr.get("action") not in SIGNAL_ACTIONS:
                raise PolicyError(
                    f"signal_rules[{i}].action must be one of {SIGNAL_ACTIONS}"
                )
            if sr["action"] == REVOKE and not (sr.get("resources") and sr.get("actions")):
                raise PolicyError(
                    f"signal_rules[{i}]: revoke rule needs resources and actions"
                )
        if body.get("default", "deny") not in ("allow", "deny"):
            raise PolicyError("default must be allow|deny")
        return cls(version=version, body=body)

    # ----- role-based authorisation ----------------------------------------

    @property
    def default_effect(self) -> str:
        return self.body.get("default", "deny")

    def rules_for(self, role: str) -> list[dict[str, Any]]:
        return [
            r
            for r in self.body.get("rules", [])
            if role in r["roles"]
            and ("*" in r["roles"] or True)
        ]

    def evaluate(self, role: str, resource: str, action: str) -> bool:
        """Return True only if an explicit allow rule wins over deny rules."""
        decision = self.default_effect == "allow"
        for rule in self.body.get("rules", []):
            if role not in rule["roles"] and "*" not in rule["roles"]:
                continue
            if not any(fnmatch.fnmatchcase(resource, pat) for pat in rule["resources"]):
                continue
            if not any(fnmatch.fnmatchcase(action, pat) for pat in rule["actions"]):
                continue
            # Last matching rule wins; rules are evaluated in document order.
            decision = rule["effect"] == "allow"
        return decision

    # ----- context constraints --------------------------------------------

    def device_min_level(self) -> int:
        return int(self.body.get("constraints", {}).get("device_min_level", 0))

    def country_allowed(self, country: Optional[str]) -> bool:
        countries = self.body.get("constraints", {}).get("network_countries")
        if not countries:
            return True
        return country in countries

    # ----- signal mapping --------------------------------------------------

    def signal_rule(self, signal: str) -> Optional[dict[str, Any]]:
        for sr in self.body.get("signal_rules", []):
            if sr["signal"] == signal:
                return sr
        return None

    def signal_action(self, signal: str) -> Optional[str]:
        rule = self.signal_rule(signal)
        return rule["action"] if rule else None


def default_policy_v1() -> dict[str, Any]:
    """Seed policy used on first boot."""
    return {
        "version": 1,
        "rules": [
            {
                "id": "admin-all",
                "roles": ["admin"],
                "resources": ["*"],
                "actions": ["*"],
                "effect": "allow",
            },
            {
                "id": "analyst-read",
                "roles": ["analyst"],
                "resources": ["dashboard/*", "reports/*"],
                "actions": ["read"],
                "effect": "allow",
            },
            {
                "id": "analyst-no-finance",
                "roles": ["analyst"],
                "resources": ["finance/*"],
                "actions": ["*"],
                "effect": "deny",
            },
        ],
        "constraints": {"device_min_level": 2, "network_countries": ["CN", "US"]},
        "signal_rules": [
            {
                "id": "kill-switch",
                "signal": "security.emergency_kill",
                "action": "terminate",
            },
            {
                "id": "device-integrity",
                "signal": "device.integrity_failure",
                "action": "revoke",
                "resources": ["*"],
                "actions": ["*"],
            },
            {
                "id": "geo-move",
                "signal": "network.country_changed",
                "action": "revoke",
                "resources": ["*"],
                "actions": ["*"],
            },
            {
                "id": "high-risk",
                "signal": "user.risk_score_high",
                "action": "reauth",
            },
            {
                "id": "device-threat",
                "signal": "device.threat_detected",
                "action": "attestation",
            },
        ],
        "default": "deny",
    }
