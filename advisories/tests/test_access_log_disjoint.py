"""Cross-app guard: ephemeral (prunable) actions must never be timeline-visible.

The access log is pruned by DROP PARTITION after the retention horizon. If an
action that routes to the access log were also shown on an advisory timeline,
dropping its month would silently erase events from advisory pages. This guard
makes that a CI failure rather than a data-loss bug. It lives in ``advisories/``
because ``audit`` must not import ``advisories`` at module level — only tests
may bridge the two apps. See INV-AUDIT-5.
"""

from advisories import timeline as tl
from audit.models import EPHEMERAL_ACTIONS, Action


def test_ephemeral_actions_are_disjoint_from_timeline():
    timeline_actions = tl.TIMELINE_ACTIONS_BY_TIER["admin_owner"]  # = tiers A | B | C
    assert EPHEMERAL_ACTIONS.isdisjoint(timeline_actions), (
        "A prunable/ephemeral action is timeline-visible — dropping its "
        "partition would erase events from advisory pages."
    )


def test_ephemeral_actions_are_a_subset_of_excluded_actions():
    assert EPHEMERAL_ACTIONS <= tl.EXCLUDED_ACTIONS


def test_ephemeral_actions_are_valid_actions():
    assert EPHEMERAL_ACTIONS <= set(Action.values)
