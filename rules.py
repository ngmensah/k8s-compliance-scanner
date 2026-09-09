"""
Deterministic rule engine.

Parses Kubernetes manifests and checks pod/container specs against the
misconfiguration patterns defined in controls.RULES. Every Finding
returned here carries a rule_id that maps to a fixed severity and a set
of compliance control citations -- none of that is decided by the AI
model.
"""

import re
from dataclasses import dataclass

import yaml

from controls import DANGEROUS_CAPABILITIES, RULES

SECRET_NAME_PATTERN = re.compile(
    r"(PASSWORD|SECRET|TOKEN|API[_-]?KEY|PRIVATE[_-]?KEY|CREDENTIAL)", re.IGNORECASE
)

# Kubernetes kinds whose pod template lives at spec.template.spec
_WORKLOAD_KINDS = {"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job"}


@dataclass
class Finding:
    rule_id: str
    resource_kind: str
    resource_name: str
    location: str
    severity_override: str = None
    detail: str = ""

    @property
    def meta(self):
        return RULES[self.rule_id]

    @property
    def title(self):
        return self.meta["title"]

    @property
    def severity(self):
        return self.severity_override or self.meta["severity"]


def load_manifest_docs(text):
    """Parse one or more YAML documents, dropping empty/None docs."""
    docs = []
    for doc in yaml.safe_load_all(text):
        if doc:
            docs.append(doc)
    return docs


def _pod_specs(doc):
    """Yield (resource_kind, resource_name, pod_spec) for any pod template in doc."""
    kind = doc.get("kind", "")
    name = doc.get("metadata", {}).get("name", "<unnamed>")
    spec = doc.get("spec") or {}

    if kind == "Pod":
        yield kind, name, spec
    elif kind in _WORKLOAD_KINDS:
        pod_spec = (spec.get("template") or {}).get("spec") or {}
        if pod_spec:
            yield kind, name, pod_spec
    elif kind == "CronJob":
        pod_spec = (
            ((spec.get("jobTemplate") or {}).get("spec") or {}).get("template") or {}
        ).get("spec") or {}
        if pod_spec:
            yield kind, name, pod_spec


def _check_pod_level(kind, name, pod_spec):
    findings = []

    if pod_spec.get("hostPID") is True:
        findings.append(Finding("host_pid", kind, name, "pod spec"))
    if pod_spec.get("hostIPC") is True:
        findings.append(Finding("host_ipc", kind, name, "pod spec"))
    if pod_spec.get("hostNetwork") is True:
        findings.append(Finding("host_network", kind, name, "pod spec"))

    pod_sc = pod_spec.get("securityContext") or {}
    pod_run_as_non_root = pod_sc.get("runAsNonRoot")

    if pod_spec.get("automountServiceAccountToken") is not False:
        findings.append(
            Finding("automount_service_account_token", kind, name, "pod spec")
        )

    containers = (pod_spec.get("containers") or []) + (
        pod_spec.get("initContainers") or []
    )
    for container in containers:
        findings.extend(
            _check_container(kind, name, container, pod_run_as_non_root)
        )

    return findings


def _check_container(kind, name, container, pod_run_as_non_root):
    findings = []
    cname = container.get("name", "<unnamed container>")
    location = f"container '{cname}'"
    sc = container.get("securityContext") or {}

    if sc.get("privileged") is True:
        findings.append(Finding("privileged_container", kind, name, location))

    run_as_user = sc.get("runAsUser")
    if run_as_user == 0:
        findings.append(Finding("explicit_root_user", kind, name, location))
    elif sc.get("runAsNonRoot") is not True and pod_run_as_non_root is not True:
        findings.append(Finding("no_run_as_non_root", kind, name, location))

    if sc.get("allowPrivilegeEscalation") is not False:
        findings.append(
            Finding("allow_privilege_escalation", kind, name, location)
        )

    capabilities = sc.get("capabilities") or {}
    added = {c.upper() for c in (capabilities.get("add") or [])}
    if added:
        dangerous = added & DANGEROUS_CAPABILITIES
        findings.append(
            Finding(
                "added_capabilities",
                kind,
                name,
                location,
                severity_override="HIGH" if dangerous else None,
                detail=", ".join(sorted(added)),
            )
        )
    dropped = {c.upper() for c in (capabilities.get("drop") or [])}
    if "ALL" not in dropped:
        findings.append(Finding("missing_cap_drop_all", kind, name, location))

    if sc.get("readOnlyRootFilesystem") is not True:
        findings.append(Finding("no_read_only_root_fs", kind, name, location))

    resources = container.get("resources") or {}
    limits = resources.get("limits") or {}
    if not ("cpu" in limits and "memory" in limits):
        findings.append(Finding("missing_resource_limits", kind, name, location))
    requests = resources.get("requests") or {}
    if not ("cpu" in requests and "memory" in requests):
        findings.append(Finding("missing_resource_requests", kind, name, location))

    image = container.get("image", "")
    if ":" not in image.split("/")[-1] or image.endswith(":latest"):
        findings.append(
            Finding("latest_image_tag", kind, name, location, detail=image)
        )

    for env_var in container.get("env") or []:
        env_name = env_var.get("name", "")
        if "value" in env_var and SECRET_NAME_PATTERN.search(env_name):
            findings.append(
                Finding(
                    "hardcoded_secret_env", kind, name, location, detail=env_name
                )
            )

    return findings


def check_manifest(text):
    """Run all deterministic checks against every doc/resource in a manifest."""
    findings = []
    for doc in load_manifest_docs(text):
        for kind, name, pod_spec in _pod_specs(doc):
            findings.extend(_check_pod_level(kind, name, pod_spec))
    return findings
