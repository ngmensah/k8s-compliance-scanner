"""
Deterministic misconfiguration-to-control mapping table.

Every finding the scanner reports maps to a rule_id in RULES below, and
every rule_id carries a fixed severity plus its compliance framework
citations. This table is the source of truth for compliance mapping —
the AI model is never asked to invent a control ID or a severity.

Reference versions used for citations:
  - CIS Kubernetes Benchmark v1.8 (section 5 - Policies)
  - NIST SP 800-53 Rev. 5
  - PCI DSS v4.0
  - SOC 2 (2017 Trust Services Criteria, as revised 2022)

CIS section numbers shift between benchmark releases and some checks
below (marked with a "note") align with the intent of a control family
rather than one official numbered control. Verify citations against the
exact benchmark version in scope before using this in an audit artifact.
"""

RULES = {
    "privileged_container": {
        "title": "Privileged container",
        "severity": "HIGH",
        "cis": "CIS Kubernetes Benchmark 5.2.1 - Minimize the admission of privileged containers",
        "nist_800_53": "AC-6 (Least Privilege), CM-7 (Least Functionality)",
        "pci_dss": "PCI DSS 7.2.1 - Restrict access to system components based on need to know",
        "soc2": "CC6.1 - Logical access security measures restrict unauthorized access",
        "remediation": "Remove securityContext.privileged (or set it to false) unless this workload has a documented, approved need for direct host device/kernel access.",
    },
    "host_pid": {
        "title": "Pod shares the host PID namespace",
        "severity": "HIGH",
        "cis": "CIS Kubernetes Benchmark 5.2.2 - Minimize the admission of containers wishing to share the host process ID namespace",
        "nist_800_53": "AC-6 (Least Privilege), SC-39 (Process Isolation)",
        "pci_dss": "PCI DSS 7.2.1 - Restrict access to system components based on need to know",
        "soc2": "CC6.1 - Logical access security measures restrict unauthorized access",
        "remediation": "Remove hostPID: true unless the workload must observe or signal host processes directly.",
    },
    "host_ipc": {
        "title": "Pod shares the host IPC namespace",
        "severity": "MEDIUM",
        "cis": "CIS Kubernetes Benchmark 5.2.3 - Minimize the admission of containers wishing to share the host IPC namespace",
        "nist_800_53": "AC-6 (Least Privilege), SC-39 (Process Isolation)",
        "pci_dss": "PCI DSS 7.2.1 - Restrict access to system components based on need to know",
        "soc2": "CC6.1 - Logical access security measures restrict unauthorized access",
        "remediation": "Remove hostIPC: true unless the workload must share host inter-process communication resources.",
    },
    "host_network": {
        "title": "Pod shares the host network namespace",
        "severity": "HIGH",
        "cis": "CIS Kubernetes Benchmark 5.2.4 - Minimize the admission of containers wishing to share the host network namespace",
        "nist_800_53": "SC-7 (Boundary Protection)",
        "pci_dss": "PCI DSS 1.4.4 - Network segmentation and boundary control between trust zones",
        "soc2": "CC6.6 - Logical access controls restrict network boundary crossing",
        "remediation": "Remove hostNetwork: true so the pod uses the cluster's overlay network instead of the node's network stack.",
    },
    "explicit_root_user": {
        "title": "Container explicitly runs as root (UID 0)",
        "severity": "HIGH",
        "cis": "CIS Kubernetes Benchmark 5.2.6 - Minimize the admission of root containers",
        "nist_800_53": "AC-6 (Least Privilege)",
        "pci_dss": "PCI DSS 7.2.1 - Restrict access to system components based on need to know",
        "soc2": "CC6.1 / CC6.3 - Least-privilege logical access",
        "remediation": "Set securityContext.runAsUser to a non-zero UID, or remove it and set runAsNonRoot: true so the image's default user is used instead of root.",
    },
    "no_run_as_non_root": {
        "title": "Container does not enforce runAsNonRoot",
        "severity": "MEDIUM",
        "cis": "CIS Kubernetes Benchmark 5.2.6 - Minimize the admission of root containers",
        "nist_800_53": "AC-6 (Least Privilege)",
        "pci_dss": "PCI DSS 7.2.1 - Restrict access to system components based on need to know",
        "soc2": "CC6.1 / CC6.3 - Least-privilege logical access",
        "remediation": "Set securityContext.runAsNonRoot: true (at the pod or container level) so the kubelet refuses to start the container if its image defaults to root.",
    },
    "allow_privilege_escalation": {
        "title": "allowPrivilegeEscalation is not disabled",
        "severity": "MEDIUM",
        "cis": "CIS Kubernetes Benchmark 5.2.5 - Minimize the admission of containers with allowPrivilegeEscalation",
        "nist_800_53": "AC-6 (Least Privilege), CM-7 (Least Functionality)",
        "pci_dss": "PCI DSS 7.2.1 - Restrict access to system components based on need to know",
        "soc2": "CC6.1 - Logical access security measures restrict unauthorized access",
        "remediation": "Set securityContext.allowPrivilegeEscalation: false so a process cannot gain more privileges than its parent.",
    },
    "added_capabilities": {
        "title": "Container adds Linux capabilities",
        "severity": "MEDIUM",
        "cis": "CIS Kubernetes Benchmark 5.2.8 / 5.2.9 - Minimize the admission of containers with added capabilities",
        "nist_800_53": "AC-6 (Least Privilege), CM-7 (Least Functionality)",
        "pci_dss": "PCI DSS 7.2.1 - Restrict access to system components based on need to know",
        "soc2": "CC6.1 - Logical access security measures restrict unauthorized access",
        "remediation": "Remove securityContext.capabilities.add. If a specific capability is required, grant only that capability and document why.",
    },
    "missing_cap_drop_all": {
        "title": "Container does not drop all default Linux capabilities",
        "severity": "LOW",
        "cis": "CIS Kubernetes Benchmark 5.2.9 - Minimize the admission of containers with capabilities assigned",
        "nist_800_53": "CM-7 (Least Functionality)",
        "pci_dss": "PCI DSS 2.2 - Configuration standards for all system components",
        "soc2": "CC6.1 - Logical access security measures restrict unauthorized access",
        "remediation": "Add securityContext.capabilities.drop: [\"ALL\"] and re-add only the specific capabilities the container actually needs.",
    },
    "no_read_only_root_fs": {
        "title": "Container filesystem is writable",
        "severity": "LOW",
        "cis": "Aligns with Pod Security Standards 'Restricted' profile (not a single numbered CIS 5.2 control)",
        "nist_800_53": "CM-7 (Least Functionality), SI-7 (Software, Firmware, and Information Integrity)",
        "pci_dss": "PCI DSS 2.2 - Configuration standards for all system components",
        "soc2": "CC6.1 - Logical access security measures restrict unauthorized access",
        "remediation": "Set securityContext.readOnlyRootFilesystem: true and mount an emptyDir volume for any paths the process must write to.",
        "note": "This maps to the intent of the Kubernetes Pod Security Standards restricted profile rather than one official numbered CIS control.",
    },
    "missing_resource_limits": {
        "title": "Container has no CPU/memory limits",
        "severity": "MEDIUM",
        "cis": "Not a numbered CIS Kubernetes Benchmark control (availability/reliability hardening, not access control)",
        "nist_800_53": "SC-5 (Denial of Service Protection)",
        "pci_dss": "N/A - operational availability control, not a PCI DSS data-security requirement",
        "soc2": "CC7.1 - System capacity is monitored and managed to meet availability commitments",
        "remediation": "Set resources.limits.cpu and resources.limits.memory so one workload cannot starve other pods on the same node.",
    },
    "missing_resource_requests": {
        "title": "Container has no CPU/memory requests",
        "severity": "LOW",
        "cis": "Not a numbered CIS Kubernetes Benchmark control (scheduling/availability hardening, not access control)",
        "nist_800_53": "SC-5 (Denial of Service Protection)",
        "pci_dss": "N/A - operational availability control, not a PCI DSS data-security requirement",
        "soc2": "CC7.1 - System capacity is monitored and managed to meet availability commitments",
        "remediation": "Set resources.requests.cpu and resources.requests.memory so the scheduler can place the pod appropriately.",
    },
    "latest_image_tag": {
        "title": "Container image is untagged or uses the 'latest' tag",
        "severity": "MEDIUM",
        "cis": "Not a numbered CIS Kubernetes Benchmark control (image supply-chain hygiene, not a benchmark check)",
        "nist_800_53": "CM-2 (Baseline Configuration), SR-3 (Supply Chain Controls and Processes)",
        "pci_dss": "PCI DSS 6.3.2 - Maintain an inventory of bespoke and custom software components",
        "soc2": "CC8.1 - Changes to infrastructure are authorized, tested, and tracked",
        "remediation": "Pin the image to an immutable tag or digest (e.g. nginx@sha256:...) so deployments are reproducible and auditable.",
    },
    "hardcoded_secret_env": {
        "title": "Hardcoded plaintext secret in an environment variable",
        "severity": "HIGH",
        "cis": "CIS Kubernetes Benchmark 5.4.1 - Prefer using Secrets as files over Secrets as environment variables",
        "nist_800_53": "IA-5 (Authenticator Management), SC-28 (Protection of Information at Rest)",
        "pci_dss": "PCI DSS 8.3 (strong authentication controls) and 6.2.4 (secure handling of credentials in code)",
        "soc2": "CC6.1 / CC6.6 - Logical access and boundary controls over sensitive data",
        "remediation": "Move the value into a Kubernetes Secret and reference it via env[].valueFrom.secretKeyRef, or use an external secrets manager. Never commit plaintext credentials into manifests.",
        "note": "CIS 5.4.1 flags any secret passed via environment variable, including one sourced from a Secret object. A literal plaintext value in the manifest itself is a more severe violation than that general control.",
    },
    "automount_service_account_token": {
        "title": "Service account token is auto-mounted",
        "severity": "LOW",
        "cis": "CIS Kubernetes Benchmark 5.1.6 - Ensure that Service Account Tokens are only mounted where necessary",
        "nist_800_53": "AC-6 (Least Privilege), IA-5 (Authenticator Management)",
        "pci_dss": "PCI DSS 7.2.1 - Restrict access to system components based on need to know",
        "soc2": "CC6.1 - Logical access security measures restrict unauthorized access",
        "remediation": "Set automountServiceAccountToken: false at the pod spec level unless the workload needs to call the Kubernetes API.",
    },
}

DANGEROUS_CAPABILITIES = {"SYS_ADMIN", "NET_ADMIN", "NET_RAW", "ALL"}

SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
