"""SLA metrics for the admin-console Stats page.

Two layers, kept apart so the arithmetic is unit-testable without a DB:

* **Layer A** — pure statistics over ``list[float]`` duration samples:
  percentiles, summaries, period windows, and period-over-period trend
  comparisons. No queries, no ``timezone.now()`` (callers pass ``now`` in)
  so tests can freeze time and assert exact values.
* **Layer B** — the ORM fetchers that turn the database into
  ``(anchor_datetime, duration_seconds)`` samples, plus
  :func:`build_stats_context`, the single entry point the view calls.

Two metrics are reported:

* **Time to first response (TTFR)** — intake/triage-sourced advisories
  only: from ``AdvisoryIntakeMetadata.submitted_at`` to the *earliest*
  audit event in :data:`FIRST_RESPONSE_ACTIONS`.
* **Time to publish (TTP)** — from ``Advisory.created_at`` to
  ``Advisory.published_at`` (set once, after a successful Git push).

Plus a **reverted** count: intake reports that were promoted to draft and
later dismissed (work undone). Both metrics are *lower is better*; samples
are **completion-anchored** (bucketed by the period their end event lands
in) so a window reports the work that *completed* in it.
"""

from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass, field

from django.db.models import Min

from advisories.models import Advisory, State
from audit.models import Action, AuditLogEntry

# ---------------------------------------------------------------------------
# Layer A — pure statistics (no DB, no clock)
# ---------------------------------------------------------------------------

#: The duration statistics every summary carries, in display order. p95 is the
#: single SLA percentile (industry standard; matches the sparkline's p95 line —
#: p90/p99 were dropped as noise at this small per-period sample size).
STAT_KEYS: tuple[str, ...] = ("mean", "p95")

#: A single sample: when the metric *completed*, and how long it took (s).
Sample = tuple[_dt.datetime, float]


@dataclass(frozen=True)
class StatSummary:
    """Mean + p95 over one window. ``None`` (with ``count == 0``) means "no
    samples" — rendered as an em dash, never as ``0`` so a quiet window doesn't
    read as "instant"."""

    count: int
    mean: float | None
    p95: float | None


@dataclass(frozen=True)
class StatComparison:
    """One statistic's current value vs its previous-period value.

    For durations ``change`` is a percentage; for counts it's the absolute
    integer delta (``is_absolute=True``). ``direction`` is the human verdict
    the template colours on — derived from a lower-is-better rule, decoupled
    from the raw sign so a green *down* arrow reads correctly.
    """

    current: float | None
    previous: float | None
    change: float | None
    direction: str  # "improved" | "worsened" | "flat" | "na"
    is_absolute: bool = False

    @property
    def magnitude(self) -> str:
        """Human change for the trend chip ("12%" / "+2" / "" when n/a)."""
        if self.change is None or self.direction == "na":
            return ""
        if self.is_absolute:
            return f"{int(round(self.change)):+d}"
        return f"{abs(self.change):.0f}%"


@dataclass(frozen=True)
class Period:
    """A trailing window and its immediately-preceding equivalent.

    ``start is None`` marks an unbounded (all-time) window; ``prev_*`` are
    ``None`` when there is no comparable previous window.
    """

    key: str
    label: str
    start: _dt.datetime | None
    end: _dt.datetime
    prev_start: _dt.datetime | None
    prev_end: _dt.datetime | None


@dataclass(frozen=True)
class PeriodMetric:
    """A duration metric (TTFR or TTP) computed for one period."""

    period_key: str
    period_label: str
    window_start: _dt.datetime | None
    window_end: _dt.datetime
    current: StatSummary
    previous: StatSummary | None
    comparisons: dict[str, StatComparison] = field(default_factory=dict)


@dataclass(frozen=True)
class CountMetric:
    """A count metric (e.g. reverted reports) computed for one period."""

    period_key: str
    period_label: str
    count: int
    comparison: StatComparison


@dataclass(frozen=True)
class TrendPoint:
    """One equal-width time bucket of the trend sparkline."""

    index: int
    start: _dt.datetime
    end: _dt.datetime
    count: int
    mean: float | None
    p95: float | None


@dataclass(frozen=True)
class Sparkline:
    """A render-ready inline-SVG line chart of mean + p95 over time, plus the
    data its HTML axes need.

    ``*_points`` are ``"x,y x,y …"`` strings for ``<polyline points>`` (only
    buckets that have data; the polyline connects across empty buckets);
    coordinates fill the ``width × height`` viewBox with larger durations higher
    up (``vmax`` at the top edge, ``0`` at the bottom), so a falling line reads
    as improving and the HTML y-labels/gridlines line up with the data.

    Axes (rendered as HTML around the SVG): ``y_ticks`` are the value labels
    ``[vmax, vmax/2, 0]`` (seconds, formatted via ``duration_human``);
    ``x_ticks`` are evenly-spaced datetimes across the span (the template labels
    the last one "now"); ``current_mean``/``current_p95`` are the latest
    non-empty bucket's values (the readout). ``has_data`` is False when every
    bucket is empty (the template shows a placeholder instead).
    """

    width: int
    height: int
    mean_points: str
    p95_points: str
    last_mean: tuple[float, float] | None
    has_data: bool
    vmax: float
    y_ticks: list[float]
    x_ticks: list[_dt.datetime]
    current_mean: float | None
    current_p95: float | None


def percentile(sorted_values: list[float], q: float) -> float | None:
    """Linear-interpolation percentile (numpy ``method="linear"`` / Postgres
    ``PERCENTILE_CONT`` semantics). ``q`` in ``[0, 1]``; ``sorted_values``
    must be pre-sorted ascending. ``None`` for an empty list; the lone value
    for a single sample (it's the best estimate of every quantile)."""
    n = len(sorted_values)
    if n == 0:
        return None
    if n == 1:
        return float(sorted_values[0])
    pos = q * (n - 1)
    lo = int(pos)
    hi = min(lo + 1, n - 1)
    frac = pos - lo
    return sorted_values[lo] + (sorted_values[hi] - sorted_values[lo]) * frac


def summarize(durations: list[float]) -> StatSummary:
    if not durations:
        return StatSummary(count=0, mean=None, p95=None)
    s = sorted(durations)
    return StatSummary(count=len(s), mean=sum(s) / len(s), p95=percentile(s, 0.95))


def _direction(current: float, previous: float, lower_is_better: bool) -> str:
    if current == previous:
        return "flat"
    decreased = current < previous
    if lower_is_better:
        return "improved" if decreased else "worsened"
    return "worsened" if decreased else "improved"


def compare(
    current: float | None, previous: float | None, *, lower_is_better: bool = True
) -> StatComparison:
    """Percentage change of a duration statistic vs the previous period.

    ``"na"`` when either side is missing or the previous value is ``0`` (no
    meaningful percentage — avoids divide-by-zero / fake ∞%)."""
    if current is None or previous is None or previous == 0:
        return StatComparison(current, previous, None, "na")
    pct = (current - previous) / previous * 100.0
    direction = "flat" if abs(pct) < 1e-9 else _direction(current, previous, lower_is_better)
    return StatComparison(current, previous, pct, direction)


def compare_count(
    current: int, previous: int | None, *, lower_is_better: bool = True
) -> StatComparison:
    """Absolute delta of a count vs the previous period. ``previous == 0`` is a
    real comparison ("+N"), not n/a; ``previous is None`` (no prior window) is
    n/a."""
    if previous is None:
        return StatComparison(float(current), None, None, "na", is_absolute=True)
    delta = float(current - previous)
    direction = "flat" if current == previous else _direction(current, previous, lower_is_better)
    return StatComparison(float(current), float(previous), delta, direction, is_absolute=True)


#: Trailing-window periods (key, label, span). Months are approximated as
#: fixed-length trailing spans so windows are always comparable.
_PERIOD_DELTAS: tuple[tuple[str, str, _dt.timedelta], ...] = (
    ("last_week", "Last week", _dt.timedelta(days=7)),
    ("last_month", "Last month", _dt.timedelta(days=30)),
    ("last_3m", "Last 3 months", _dt.timedelta(days=90)),
    ("last_6m", "Last 6 months", _dt.timedelta(days=180)),
    ("last_12m", "Last 12 months", _dt.timedelta(days=365)),
)


def build_periods(now: _dt.datetime) -> list[Period]:
    """The predefined periods, anchored on ``now``. ``all_time`` is last and
    has no previous window."""
    periods = [
        Period(key, label, now - delta, now, now - delta - delta, now - delta)
        for key, label, delta in _PERIOD_DELTAS
    ]
    periods.append(Period("all_time", "All time", None, now, None, None))
    return periods


def custom_period(start: _dt.datetime, end: _dt.datetime) -> Period:
    """A user-supplied range; its previous window is the equal-length span
    ending where this one starts."""
    span = end - start
    return Period("custom", "Custom range", start, end, start - span, start)


def _in_window(anchor: _dt.datetime, start: _dt.datetime | None, end: _dt.datetime) -> bool:
    """Half-open ``[start, end)``; ``start is None`` means unbounded below."""
    if start is not None and anchor < start:
        return False
    return anchor < end


def compute_period_metric(
    samples: list[Sample], period: Period, *, lower_is_better: bool = True
) -> PeriodMetric:
    current = summarize([d for a, d in samples if _in_window(a, period.start, period.end)])
    previous: StatSummary | None = None
    if period.prev_start is not None and period.prev_end is not None:
        previous = summarize(
            [d for a, d in samples if _in_window(a, period.prev_start, period.prev_end)]
        )
    comparisons = {
        key: compare(
            getattr(current, key),
            getattr(previous, key) if previous else None,
            lower_is_better=lower_is_better,
        )
        for key in STAT_KEYS
    }
    return PeriodMetric(
        period.key, period.label, period.start, period.end, current, previous, comparisons
    )


def compute_count_metric(
    samples: list[Sample], period: Period, *, lower_is_better: bool = True
) -> CountMetric:
    current = sum(1 for a, _ in samples if _in_window(a, period.start, period.end))
    previous: int | None = None
    if period.prev_start is not None and period.prev_end is not None:
        previous = sum(1 for a, _ in samples if _in_window(a, period.prev_start, period.prev_end))
    return CountMetric(
        period.key,
        period.label,
        current,
        compare_count(current, previous, lower_is_better=lower_is_better),
    )


# --- Trend sparkline ---------------------------------------------------------

#: Trend sparkline span: 12 trailing 30-day buckets (≈ last 12 months). Fixed
#: width keeps it consistent with the page's trailing-window period model.
SERIES_BUCKETS = 12
SERIES_BUCKET = _dt.timedelta(days=30)

# SVG viewBox geometry (unitless; CSS sizes the element via a matching
# ``aspect-ratio`` so scaling is uniform — the marker dot stays round).
_SPARK_W, _SPARK_H, _SPARK_PAD = 240, 40, 4


def bucket_series(
    samples: list[Sample],
    now: _dt.datetime,
    *,
    count: int = SERIES_BUCKETS,
    delta: _dt.timedelta = SERIES_BUCKET,
) -> list[TrendPoint]:
    """Summarise ``samples`` into ``count`` equal trailing buckets, oldest→newest.

    Each bucket is half-open ``[start, end)`` and reuses :func:`summarize`;
    a bucket with no samples carries ``None`` for mean/p95."""
    edges: list[tuple[_dt.datetime, _dt.datetime]] = []
    end = now
    for _ in range(count):
        edges.append((end - delta, end))
        end = end - delta
    edges.reverse()
    points: list[TrendPoint] = []
    for i, (start, bend) in enumerate(edges):
        bucket = [d for a, d in samples if _in_window(a, start, bend)]
        s = summarize(bucket)
        points.append(TrendPoint(i, start, bend, s.count, s.mean, s.p95))
    return points


def _empty_sparkline(width: int, height: int) -> Sparkline:
    return Sparkline(
        width,
        height,
        "",
        "",
        None,
        has_data=False,
        vmax=0.0,
        y_ticks=[],
        x_ticks=[],
        current_mean=None,
        current_p95=None,
    )


def build_sparkline(
    points: list[TrendPoint],
    *,
    width: int = _SPARK_W,
    height: int = _SPARK_H,
    pad: int = _SPARK_PAD,
) -> Sparkline:
    """Map trend points to SVG polyline coordinates for mean + p95, plus axis data.

    Both series share one y-scale (the max across all present mean+p95 values),
    so p95 always plots at or above mean. ``y`` uses the **full** height (``vmax``
    at the top edge, ``0`` at the bottom) — no vertical padding — so the HTML
    y-axis labels and CSS gridlines line up with the data; ``pad`` insets only the
    x extent. Empty buckets are skipped; the polyline connects across the gap.
    """
    n = len(points)
    values = [v for p in points for v in (p.mean, p.p95) if v is not None]
    if n == 0 or not values:
        return _empty_sparkline(width, height)
    vmax = max(values)
    span_x = width - 2 * pad

    def x_of(index: int) -> float:
        if n == 1:
            return width / 2
        return pad + index * span_x / (n - 1)

    def y_of(value: float) -> float:
        # vmax == 0 (all-zero durations) → flat line at the baseline.
        frac = 0.0 if vmax == 0 else value / vmax
        return (1 - frac) * height

    def coords(attr: str) -> list[tuple[float, float]]:
        out = []
        for p in points:
            v = getattr(p, attr)
            if v is not None:
                out.append((round(x_of(p.index), 1), round(y_of(v), 1)))
        return out

    def to_str(pairs: list[tuple[float, float]]) -> str:
        return " ".join(f"{x},{y}" for x, y in pairs)

    # x-axis ticks: ~5 evenly-spaced bucket starts, oldest → newest, then the
    # span end (labelled "now" by the template).
    step = max(1, n // 4)
    tick_idxs = list(range(0, n, step))[:4]
    x_ticks = [points[i].start for i in tick_idxs] + [points[-1].end]

    # Readout: the most recent non-empty bucket's mean / p95.
    current_mean = current_p95 = None
    for p in reversed(points):
        if p.mean is not None:
            current_mean, current_p95 = p.mean, p.p95
            break

    mean_pairs = coords("mean")
    p95_pairs = coords("p95")
    return Sparkline(
        width,
        height,
        to_str(mean_pairs),
        to_str(p95_pairs),
        mean_pairs[-1] if mean_pairs else None,
        has_data=True,
        vmax=vmax,
        y_ticks=[vmax, vmax / 2, 0.0],
        x_ticks=x_ticks,
        current_mean=current_mean,
        current_p95=current_p95,
    )


# ---------------------------------------------------------------------------
# Layer B — ORM fetchers (turn the DB into samples)
# ---------------------------------------------------------------------------

# --- EDIT HERE to refine what "first response" means ------------------------
# The audit actions that count as the security team's first response to an
# intake report. Order is irrelevant — the *earliest* one per advisory wins,
# so a report promoted and later dismissed is timed from its promotion.
# ``ADVISORY_DISMISSED`` fires for both a triage rejection (a genuine first
# response) and a post-promotion draft dismissal; ``Min`` makes this safe
# because a promotion, when present, always precedes any draft dismissal.
FIRST_RESPONSE_ACTIONS: frozenset[str] = frozenset(
    {
        Action.ADVISORY_TRIAGE_PROMOTED,
        Action.ADVISORY_DISMISSED,
        Action.ADVISORY_FLAGGED_FOR_ROUTING,
    }
)
# ----------------------------------------------------------------------------


def fetch_ttp_samples(project_slug: str | None = None) -> list[Sample]:
    """Published advisories, anchored on ``published_at``; duration =
    ``published_at - created_at``. Negative durations (clock skew) dropped.
    Scoped to one project when ``project_slug`` is given."""
    qs = Advisory.objects.filter(state=State.PUBLISHED, published_at__isnull=False)
    if project_slug:
        qs = qs.filter(project__slug=project_slug)
    out: list[Sample] = []
    for published_at, created_at in qs.values_list("published_at", "created_at"):
        if published_at is None:  # narrows the nullable field for the type checker
            continue
        dur = (published_at - created_at).total_seconds()
        if dur >= 0:
            out.append((published_at, dur))
    return out


def fetch_ttfr_samples(project_slug: str | None = None) -> list[Sample]:
    """Intake reports, anchored on the first-response time; duration =
    first-response − submission. Reports never responded to (no completion
    event) are absent — correct under completion-anchoring. Scoped to one
    project when ``project_slug`` is given.

    One grouped query: filter first-response audit events to advisories that
    have an intake sidecar (``advisory__intake``), pulling the submitted-at
    over the join — no Python id round-trip / ``IN`` list. Riding the ``action``
    and ``(advisory, created_at)`` indexes + the intake OneToOne."""
    qs = AuditLogEntry.objects.filter(
        action__in=FIRST_RESPONSE_ACTIONS, advisory__intake__isnull=False
    )
    if project_slug:
        qs = qs.filter(advisory__project__slug=project_slug)
    out: list[Sample] = []
    for row in qs.values("advisory_id", "advisory__intake__submitted_at").annotate(
        first_at=Min("created_at")
    ):
        submitted_at = row["advisory__intake__submitted_at"]
        first_at = row["first_at"]
        if submitted_at is None or first_at is None:
            continue
        dur = (first_at - submitted_at).total_seconds()
        if dur >= 0:
            out.append((first_at, dur))
    return out


def fetch_reverted_samples(project_slug: str | None = None) -> list[Sample]:
    """Intake reports promoted to draft and *later* dismissed, anchored on the
    dismissal. The sample's duration is a placeholder (this feeds a count, not
    a percentile). Scoped to one project when ``project_slug`` is given.

    Two grouped queries over an intake-scoped base (the ``advisory__intake``
    join replaces the old all-intake-ids ``IN`` list): the earliest promotion
    per advisory, and the earliest dismissal; combined in Python keeping only
    advisories whose dismissal followed a promotion."""
    base = AuditLogEntry.objects.filter(advisory__intake__isnull=False)
    if project_slug:
        base = base.filter(advisory__project__slug=project_slug)
    promoted = dict(
        base.filter(action=Action.ADVISORY_TRIAGE_PROMOTED)
        .values("advisory_id")
        .annotate(at=Min("created_at"))
        .values_list("advisory_id", "at")
    )
    if not promoted:
        return []
    out: list[Sample] = []
    for advisory_id, dismissed_at in (
        base.filter(action=Action.ADVISORY_DISMISSED)
        .values("advisory_id")
        .annotate(at=Min("created_at"))
        .values_list("advisory_id", "at")
    ):
        promoted_at = promoted.get(advisory_id)
        if promoted_at is not None and dismissed_at is not None and dismissed_at > promoted_at:
            out.append((dismissed_at, 0.0))
    return out


def build_stats_context(
    now: _dt.datetime, *, custom: Period | None = None, project_slug: str | None = None
) -> dict:
    """Fetch each sample set once and compute every period's metrics.

    Returns ``ttfr_rows`` (each a dict of the TTFR ``PeriodMetric`` and its
    paired reverted ``CountMetric``) and ``ttp_rows`` (TTP ``PeriodMetric``).
    A custom range, when given, is appended as a final period in every list.
    ``project_slug`` scopes every metric (tables + sparklines) to one project.
    """
    periods = build_periods(now)
    if custom is not None:
        periods.append(custom)
    ttp = fetch_ttp_samples(project_slug)
    ttfr = fetch_ttfr_samples(project_slug)
    reverted = fetch_reverted_samples(project_slug)
    return {
        "ttfr_rows": [
            {
                "metric": compute_period_metric(ttfr, p),
                "reverted": compute_count_metric(reverted, p),
            }
            for p in periods
        ],
        "ttp_rows": [compute_period_metric(ttp, p) for p in periods],
        # Per-metric 12-month trend sparklines, from the same fetched samples.
        "ttfr_sparkline": build_sparkline(bucket_series(ttfr, now)),
        "ttp_sparkline": build_sparkline(bucket_series(ttp, now)),
    }
