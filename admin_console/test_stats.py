"""Unit tests for the pure statistics layer of the admin Stats page.

No database: these exercise percentile interpolation, summaries, trend
comparisons, period-window arithmetic, and the half-open bucketing in
:mod:`admin_console.stats` against frozen inputs.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from admin_console.stats import (
    TrendPoint,
    bucket_series,
    build_periods,
    build_sparkline,
    compare,
    compare_count,
    compute_count_metric,
    compute_period_metric,
    custom_period,
    percentile,
    summarize,
)

NOW = datetime(2026, 6, 15, 12, 0, tzinfo=UTC)


# ----- percentile --------------------------------------------------------


def test_percentile_linear_interpolation():
    # pos = 0.9 * (4-1) = 2.7 → between index 2 (=3) and 3 (=4): 3 + 0.7 = 3.7
    assert percentile([1.0, 2.0, 3.0, 4.0], 0.90) == 3.7


def test_percentile_endpoints_are_min_and_max():
    assert percentile([10.0, 20.0, 30.0], 0.0) == 10.0
    assert percentile([10.0, 20.0, 30.0], 1.0) == 30.0


def test_percentile_empty_is_none_and_single_is_value():
    assert percentile([], 0.95) is None
    assert percentile([42.0], 0.95) == 42.0


# ----- summarize ---------------------------------------------------------


def test_summarize_empty():
    s = summarize([])
    assert s.count == 0
    assert s.mean is s.p95 is None


def test_summarize_single_sample_collapses():
    s = summarize([7.0])
    assert s.count == 1
    assert s.mean == s.p95 == 7.0


def test_summarize_mean_below_p95():
    # Uniform 1..100: mean 50.5, p95 95.05 — p95 sits well above the mean.
    s = summarize([float(x) for x in range(1, 101)])
    assert s.count == 100
    assert s.mean == 50.5
    assert s.mean is not None and s.p95 is not None
    assert s.mean < s.p95


# ----- compare (durations) ----------------------------------------------


def test_compare_lower_is_better_improved_and_worsened():
    improved = compare(10.0, 20.0, lower_is_better=True)
    assert improved.direction == "improved"
    assert improved.change == -50.0
    assert improved.magnitude == "50%"

    worsened = compare(20.0, 10.0, lower_is_better=True)
    assert worsened.direction == "worsened"


def test_compare_flat_and_na_guards():
    assert compare(10.0, 10.0).direction == "flat"
    assert compare(None, 5.0).direction == "na"
    assert compare(5.0, None).direction == "na"
    # previous == 0 has no meaningful percentage.
    assert compare(5.0, 0.0).direction == "na"
    assert compare(None, 5.0).magnitude == ""


# ----- compare_count -----------------------------------------------------


def test_compare_count_absolute_delta_and_direction():
    fewer = compare_count(1, 3, lower_is_better=True)
    assert fewer.direction == "improved"
    assert fewer.is_absolute is True
    assert fewer.magnitude == "-2"

    more = compare_count(3, 1, lower_is_better=True)
    assert more.direction == "worsened"
    assert more.magnitude == "+2"


def test_compare_count_zero_previous_is_real_comparison():
    # Unlike durations, a zero previous count is a real baseline, not n/a.
    c = compare_count(2, 0, lower_is_better=True)
    assert c.direction == "worsened"
    assert c.magnitude == "+2"
    assert compare_count(0, 0).direction == "flat"


def test_compare_count_no_previous_window_is_na():
    assert compare_count(2, None).direction == "na"


# ----- periods -----------------------------------------------------------


def test_build_periods_windows_and_all_time_last():
    periods = build_periods(NOW)
    keys = [p.key for p in periods]
    assert keys == ["last_week", "last_month", "last_3m", "last_6m", "last_12m", "all_time"]

    week = periods[0]
    assert week.start == NOW - timedelta(days=7)
    assert week.end == NOW
    assert week.prev_start == NOW - timedelta(days=14)
    assert week.prev_end == NOW - timedelta(days=7)

    all_time = periods[-1]
    assert all_time.start is None
    assert all_time.prev_start is None and all_time.prev_end is None


def test_custom_period_previous_is_equal_preceding_span():
    start = NOW - timedelta(days=10)
    end = NOW
    p = custom_period(start, end)
    assert p.key == "custom"
    assert p.start == start and p.end == end
    assert p.prev_start == start - timedelta(days=10)
    assert p.prev_end == start


# ----- compute_period_metric (windowing) --------------------------------


def test_compute_period_metric_half_open_window_boundaries():
    week = build_periods(NOW)[0]  # [now-7d, now)
    samples = [
        (week.start, 100.0),  # exactly at start → included
        (week.end, 200.0),  # exactly at end → excluded
        (week.start + timedelta(hours=1), 50.0),  # inside → included
    ]
    metric = compute_period_metric(samples, week)
    assert metric.current.count == 2
    assert metric.current.mean == 75.0


def test_compute_period_metric_previous_window_does_not_leak():
    week = build_periods(NOW)[0]
    samples = [
        (NOW - timedelta(days=1), 10.0),  # current window
        (NOW - timedelta(days=10), 99.0),  # previous window only
    ]
    metric = compute_period_metric(samples, week)
    assert metric.current.count == 1
    assert metric.previous is not None and metric.previous.count == 1
    assert metric.comparisons["mean"].direction in {"improved", "worsened", "flat"}


def test_compute_period_metric_empty_window_is_na():
    week = build_periods(NOW)[0]
    metric = compute_period_metric([], week)
    assert metric.current.count == 0
    assert metric.comparisons["mean"].direction == "na"


def test_compute_count_metric_counts_and_compares():
    week = build_periods(NOW)[0]
    samples = [
        (NOW - timedelta(days=1), 0.0),
        (NOW - timedelta(days=2), 0.0),
        (NOW - timedelta(days=10), 0.0),  # previous window
    ]
    metric = compute_count_metric(samples, week)
    assert metric.count == 2
    assert metric.comparison.direction == "worsened"  # 2 now vs 1 before → more reverts
    assert metric.comparison.magnitude == "+1"


# ----- bucket_series (trend sparkline buckets) --------------------------


def _pairs(points_str):
    """Parse a sparkline 'x,y x,y' string into a list of (float, float)."""
    return (
        [tuple(float(n) for n in pair.split(",")) for pair in points_str.split()]
        if points_str
        else []
    )


def test_bucket_series_oldest_to_newest_and_assignment():
    samples = [
        (NOW - timedelta(days=25), 100.0),  # oldest bucket
        (NOW - timedelta(days=15), 200.0),  # middle
        (NOW - timedelta(days=5), 300.0),  # newest
        (NOW - timedelta(days=5), 100.0),  # newest (second)
    ]
    points = bucket_series(samples, NOW, count=3, delta=timedelta(days=10))
    assert [p.index for p in points] == [0, 1, 2]
    assert points[0].start < points[1].start < points[2].start  # oldest → newest
    assert points[0].count == 1 and points[0].mean == 100.0
    assert points[1].count == 1 and points[1].mean == 200.0
    assert points[2].count == 2 and points[2].mean == 200.0  # (300+100)/2


def test_bucket_series_empty_bucket_is_none_and_boundary_inclusive():
    # One sample exactly on a bucket start (now-20d) lands in the *newer* bucket
    # (half-open [start, end)); the oldest bucket stays empty.
    points = bucket_series(
        [(NOW - timedelta(days=20), 50.0)], NOW, count=3, delta=timedelta(days=10)
    )
    assert points[0].count == 0 and points[0].mean is None and points[0].p95 is None
    assert points[1].count == 1 and points[1].mean == 50.0
    assert points[2].count == 0


# ----- build_sparkline (SVG geometry) -----------------------------------


def _tp(index, mean, p95):
    base = NOW - timedelta(days=300)
    return TrendPoint(index, base, base + timedelta(days=30), 0 if mean is None else 1, mean, p95)


def test_build_sparkline_skips_gaps_and_inverts_y():
    points = [_tp(0, 10.0, 20.0), _tp(1, None, None), _tp(2, 5.0, 8.0)]
    spark = build_sparkline(points, width=240, height=40, pad=4)
    assert spark.has_data is True
    mean_pairs = _pairs(spark.mean_points)
    p95_pairs = _pairs(spark.p95_points)
    assert len(mean_pairs) == 2  # the empty middle bucket is skipped
    assert len(p95_pairs) == 2
    # Full-height scale: the overall max (p95 of point 0 = 20) sits at the top edge (y == 0).
    assert p95_pairs[0][1] == 0.0
    # y is inverted: the larger mean (10 at index 0) is higher up (smaller y)
    # than the smaller mean (5 at index 2).
    assert mean_pairs[0][1] < mean_pairs[1][1]
    # last_mean marks the latest present mean point (index 2, far right).
    assert spark.last_mean is not None
    assert spark.last_mean[0] == mean_pairs[-1][0]
    assert mean_pairs[-1][0] > mean_pairs[0][0]


def test_build_sparkline_all_empty_has_no_data():
    spark = build_sparkline([_tp(0, None, None), _tp(1, None, None)])
    assert spark.has_data is False
    assert spark.mean_points == "" and spark.p95_points == ""
    assert spark.last_mean is None
    assert spark.y_ticks == [] and spark.x_ticks == []
    assert spark.current_mean is None and spark.current_p95 is None


def test_build_sparkline_single_point_centered():
    spark = build_sparkline([_tp(0, 5.0, 10.0)], width=240, height=40, pad=4)
    assert spark.has_data is True
    assert _pairs(spark.mean_points)[0][0] == 120.0  # width / 2


def test_build_sparkline_axis_ticks_and_readout():
    base = NOW - timedelta(days=120)
    pts = [
        TrendPoint(
            i,
            base + timedelta(days=30 * i),
            base + timedelta(days=30 * (i + 1)),
            0 if i == 1 else 1,
            None if i == 1 else float(10 * (i + 1)),  # mean: 10, _, 30, 40
            None if i == 1 else float(20 * (i + 1)),  # p95:  20, _, 60, 80
        )
        for i in range(4)
    ]
    spark = build_sparkline(pts)
    assert spark.vmax == 80.0  # max across all present mean + p95
    assert spark.y_ticks == [80.0, 40.0, 0.0]  # max / mid / 0
    # Readout = the latest non-empty bucket (index 3).
    assert spark.current_mean == 40.0 and spark.current_p95 == 80.0
    # x-ticks span oldest → newest, last == the span end (template labels it "now").
    assert spark.x_ticks[0] == pts[0].start
    assert spark.x_ticks[-1] == pts[-1].end
    assert spark.x_ticks == sorted(spark.x_ticks)
