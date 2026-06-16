from django.urls import path

from . import views, views_workflow

app_name = "advisories"

urlpatterns = [
    path("", views.advisory_list, name="list"),
    path("new/", views.advisory_create, name="create"),
    path("<advid:advisory_id>/", views.advisory_detail, name="detail"),
    path("<advid:advisory_id>/edit/", views.advisory_edit, name="edit"),
    path("<advid:advisory_id>/dismiss/", views.advisory_dismiss, name="dismiss"),
    path("<advid:advisory_id>/reopen/", views.advisory_reopen, name="reopen"),
    path("<advid:advisory_id>/promote/", views.advisory_promote, name="promote"),
    path("<advid:advisory_id>/flag/", views.advisory_flag, name="flag"),
    path("<advid:advisory_id>/flag/modal/", views.advisory_flag_modal, name="flag_modal"),
    path(
        "<advid:advisory_id>/clear-routing-flag/",
        views.advisory_clear_routing_flag,
        name="clear_routing_flag",
    ),
    path(
        "<advid:advisory_id>/request-reassignment/modal/",
        views.advisory_request_reassignment_modal,
        name="request_reassignment_modal",
    ),
    path(
        "<advid:advisory_id>/request-reassignment/",
        views.advisory_request_reassignment,
        name="request_reassignment",
    ),
    path(
        "<advid:advisory_id>/withdraw-reassignment/modal/",
        views.advisory_withdraw_reassignment_modal,
        name="withdraw_reassignment_modal",
    ),
    path(
        "<advid:advisory_id>/withdraw-reassignment/",
        views.advisory_withdraw_reassignment,
        name="withdraw_reassignment",
    ),
    path(
        "<advid:advisory_id>/accept-reassignment/",
        views.advisory_accept_reassignment,
        name="accept_reassignment",
    ),
    path(
        "<advid:advisory_id>/access-review/dismiss/",
        views.advisory_access_review_dismiss,
        name="access_review_dismiss",
    ),
    path("<advid:advisory_id>/request-cve/", views_workflow.request_cve, name="request_cve"),
    path("<advid:advisory_id>/unassign-cve/", views_workflow.unassign_cve, name="unassign_cve"),
    path(
        "<advid:advisory_id>/submit-review/", views_workflow.submit_for_review, name="submit_review"
    ),
    path("<advid:advisory_id>/reopen-review/", views_workflow.reopen_review, name="reopen_review"),
    path(
        "<advid:advisory_id>/withdraw-review/",
        views_workflow.withdraw_review,
        name="withdraw_review",
    ),
    path(
        "<advid:advisory_id>/revoke-approval/",
        views_workflow.revoke_approval,
        name="revoke_approval",
    ),
    path(
        "<advid:advisory_id>/review/decide/",
        views_workflow.review_decide,
        name="review_decide",
    ),
    path("<advid:advisory_id>/history/", views.advisory_history, name="history"),
    path(
        "<advid:advisory_id>/details-history/",
        views.advisory_details_history,
        name="details_history",
    ),
    path(
        "<advid:advisory_id>/versions/<int:version_id>/diff/",
        views.advisory_version_diff,
        name="version_diff",
    ),
]
