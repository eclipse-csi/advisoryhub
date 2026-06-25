"""Admin console views — re-exports for the URLConf."""

from .access_log import access_log
from .audit import audit
from .cves import (
    cve_allow,
    cve_reject_modal,
    cve_transition,
    cves,
    orphan_mark_rejected,
    orphan_reassignment_resolve,
)
from .ghsa import ghsa_dashboard
from .groups import group_detail, group_list
from .inbox import inbox
from .invitations import invitation_list, invitation_resend, invitation_revoke
from .maintenance import maintenance
from .projects import project_create, project_edit, project_list, project_sync_roster
from .publications import publications
from .stats import stats
from .users import user_ban, user_detail, user_forget, user_list, user_unban

# The URL conf historically referred to the inbox view as ``index``; keep
# that alias so URL patterns and existing tests stay stable.
index = inbox

__all__ = [
    "access_log",
    "audit",
    "cve_allow",
    "cve_reject_modal",
    "cve_transition",
    "cves",
    "ghsa_dashboard",
    "group_detail",
    "group_list",
    "index",
    "inbox",
    "invitation_list",
    "invitation_resend",
    "invitation_revoke",
    "maintenance",
    "orphan_mark_rejected",
    "orphan_reassignment_resolve",
    "project_create",
    "project_edit",
    "project_list",
    "project_sync_roster",
    "publications",
    "stats",
    "user_ban",
    "user_detail",
    "user_forget",
    "user_list",
    "user_unban",
]
