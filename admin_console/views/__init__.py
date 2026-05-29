"""Admin console views — re-exports for the URLConf."""

from .audit import audit
from .cves import (
    cve_reject_modal,
    cve_transition,
    cves,
    orphan_mark_rejected,
    orphan_reassignment_resolve,
)
from .groups import group_detail, group_list
from .inbox import inbox
from .maintenance import maintenance
from .projects import project_create, project_edit, project_list
from .publications import publications
from .users import user_detail, user_list

# The URL conf historically referred to the inbox view as ``index``; keep
# that alias so URL patterns and existing tests stay stable.
index = inbox

__all__ = [
    "audit",
    "cve_reject_modal",
    "cve_transition",
    "cves",
    "group_detail",
    "group_list",
    "index",
    "inbox",
    "maintenance",
    "orphan_mark_rejected",
    "orphan_reassignment_resolve",
    "project_create",
    "project_edit",
    "project_list",
    "publications",
    "user_detail",
    "user_list",
]
