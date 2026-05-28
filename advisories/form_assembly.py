"""Build and assemble advisory list formsets.

The six list-shaped advisory fields (aliases, cwe_ids, references,
severity, credits, affected) are edited via :mod:`django.forms.formsets`
rather than raw JSON textareas. This module owns:

* Transforming an :class:`Advisory` into the ``initial=`` data each
  formset expects on the GET path.
* Constructing all the formsets — including the inner events formsets
  nested under each :class:`AffectedForm`.
* Reassembling cleaned formset data back into the JSON-list shape the
  model fields and downstream OSV/CSAF builders expect.
* Validating the bundle and surfacing model-level ``full_clean`` errors
  back onto the bound form — shared between the advisory edit/create
  flow and the public intake submission flow.

The view (:func:`advisories.views.advisory_edit` and friends, and
:func:`intake.views.report_form`) drives the flow; this module is pure
functions over Django formsets and the :class:`Advisory` model.
"""

from __future__ import annotations

from typing import Any

from django.core.exceptions import ValidationError

from .forms import ECOSYSTEM_DATALIST_ID, LIST_FORMSETS, OSV_ECOSYSTEMS, EventFormSet

# ---------------------------------------------------------------------------
# Initial-data transforms (DB → formset ``initial``)
# ---------------------------------------------------------------------------


def _aliases_initial(advisory) -> list[dict]:
    return [{"value": s} for s in (advisory.aliases if advisory else []) or []]


def _cwe_initial(advisory) -> list[dict]:
    return [{"value": s} for s in (advisory.cwe_ids if advisory else []) or []]


def _refs_initial(advisory) -> list[dict]:
    return [
        {"type": r.get("type", "WEB"), "url": r.get("url", "")}
        for r in (advisory.references if advisory else []) or []
    ]


def _severity_initial(advisory) -> list[dict]:
    rows: list[dict] = []
    for s in (advisory.severity if advisory else []) or []:
        stype = s.get("type", "")
        score = s.get("score", "")
        # Split into the right input based on type so the matching widget
        # renders pre-filled and the other stays blank.
        if stype == "Ubuntu":
            rows.append({"type": stype, "score": "", "score_ubuntu": score})
        else:
            rows.append({"type": stype, "score": score, "score_ubuntu": ""})
    return rows


def _credits_initial(advisory) -> list[dict]:
    return [
        {"name": c.get("name", ""), "type": c.get("type", "")}
        for c in (advisory.credits if advisory else []) or []
    ]


def _affected_initial(advisory) -> list[dict]:
    """Explode each (package, range) pair into one outer row.

    OSV allows multiple ``affected`` entries to share a package; we use
    that here so the UI can stay flat: one outer row → one range. When an
    advisory has multiple ranges grouped under a single ``affected`` entry,
    the GET path produces one row per range, and ``versions`` is attached
    only to the first exploded row to keep the round-trip deterministic.
    """
    rows: list[dict] = []
    for entry in (advisory.affected if advisory else []) or []:
        pkg = entry.get("package") or {}
        pkg_name = pkg.get("name", "")
        ecosystem = pkg.get("ecosystem", "")
        purl = pkg.get("purl", "")
        ranges = entry.get("ranges") or []
        versions = entry.get("versions") or []
        versions_str = "\n".join(versions)
        if ranges:
            for i, r in enumerate(ranges):
                rows.append(
                    {
                        "package_name": pkg_name,
                        "package_ecosystem": ecosystem,
                        "package_purl": purl,
                        "range_type": r.get("type", ""),
                        "versions": versions_str if i == 0 else "",
                    }
                )
        elif versions:
            rows.append(
                {
                    "package_name": pkg_name,
                    "package_ecosystem": ecosystem,
                    "package_purl": purl,
                    "range_type": "",
                    "versions": versions_str,
                }
            )
    return rows


def _affected_events_initial(advisory) -> list[list[dict]]:
    """Per-row events ``initial`` lists, aligned with :func:`_affected_initial`."""
    rows: list[list[dict]] = []
    for entry in (advisory.affected if advisory else []) or []:
        ranges = entry.get("ranges") or []
        versions = entry.get("versions") or []
        if ranges:
            for r in ranges:
                rows.append(
                    [
                        {"kind": k, "value": v}
                        for ev in (r.get("events") or [])
                        for k, v in ev.items()
                    ]
                )
        elif versions:
            rows.append([])
    return rows


_INITIAL_BUILDERS = {
    "aliases": _aliases_initial,
    "cwe_ids": _cwe_initial,
    "references": _refs_initial,
    "severity": _severity_initial,
    "credits": _credits_initial,
    "affected": _affected_initial,
}


# ---------------------------------------------------------------------------
# Formset construction
# ---------------------------------------------------------------------------


def build_formsets(request, advisory) -> dict[str, Any]:
    """Build the six top-level formsets, bound to POST data when present."""
    is_post = request.method == "POST"
    data = request.POST if is_post else None
    formsets: dict[str, Any] = {}
    for name, klass in LIST_FORMSETS.items():
        if is_post:
            formsets[name] = klass(data, prefix=name)
        else:
            formsets[name] = klass(prefix=name, initial=_INITIAL_BUILDERS[name](advisory))
    return formsets


def build_event_formsets(request, outer_formset, advisory) -> list:
    """One :class:`EventFormSet` per outer affected row.

    On POST we trust ``outer_formset.total_form_count()`` to drive how
    many inner formsets we instantiate, because Django parses POST data
    by prefix and the inner data is already there regardless of whether
    the outer formset has been declared valid yet.
    """
    is_post = request.method == "POST"
    data = request.POST if is_post else None
    if is_post:
        n = outer_formset.total_form_count()
    else:
        n = len(outer_formset.forms)
    initials = _affected_events_initial(advisory)
    inner: list = []
    for i in range(n):
        prefix = f"affected-{i}-events"
        if is_post:
            inner.append(EventFormSet(data, prefix=prefix))
        else:
            init = initials[i] if i < len(initials) else []
            inner.append(EventFormSet(prefix=prefix, initial=init))
    return inner


# ---------------------------------------------------------------------------
# Assembly (formset cleaned_data → JSON for the model)
# ---------------------------------------------------------------------------


def _row_data(fs) -> list[dict]:
    """Cleaned, non-deleted, non-empty rows from a formset."""
    out: list[dict] = []
    for f in fs.forms:
        if not hasattr(f, "cleaned_data"):
            continue
        cd = f.cleaned_data
        if not cd or cd.get("DELETE"):
            continue
        out.append(cd)
    return out


def assemble_json(formsets: dict[str, Any], event_formsets: list) -> dict[str, list]:
    """Turn cleaned formset data back into the JSON shape model fields expect."""
    aliases = [r["value"] for r in _row_data(formsets["aliases"])]
    cwe_ids = [r["value"] for r in _row_data(formsets["cwe_ids"])]
    references = [{"type": r["type"], "url": r["url"]} for r in _row_data(formsets["references"])]
    severity = [{"type": r["type"], "score": r["score"]} for r in _row_data(formsets["severity"])]
    credits = []
    for r in _row_data(formsets["credits"]):
        entry: dict[str, str] = {"name": r["name"]}
        if r.get("type"):
            entry["type"] = r["type"]
        credits.append(entry)

    affected: list[dict] = []
    for i, outer in enumerate(formsets["affected"].forms):
        if not hasattr(outer, "cleaned_data"):
            continue
        cd = outer.cleaned_data
        if not cd or cd.get("DELETE") or not cd.get("package_name"):
            continue
        pkg: dict[str, str] = {"name": cd["package_name"]}
        if cd.get("package_ecosystem"):
            pkg["ecosystem"] = cd["package_ecosystem"]
        if cd.get("package_purl"):
            pkg["purl"] = cd["package_purl"]
        aff_entry: dict[str, Any] = {"package": pkg}
        events = [{ev["kind"]: ev["value"]} for ev in _row_data(event_formsets[i])]
        if cd.get("range_type") and events:
            aff_entry["ranges"] = [{"type": cd["range_type"], "events": events}]
        versions_text = (cd.get("versions") or "").strip()
        if versions_text:
            aff_entry["versions"] = [v.strip() for v in versions_text.splitlines() if v.strip()]
        if "ranges" in aff_entry or "versions" in aff_entry:
            affected.append(aff_entry)

    return {
        "aliases": aliases,
        "cwe_ids": cwe_ids,
        "references": references,
        "severity": severity,
        "credits": credits,
        "affected": affected,
    }


# ---------------------------------------------------------------------------
# Validation + context (shared with intake view)
# ---------------------------------------------------------------------------


def validate_all(form, formsets, event_formsets) -> bool:
    """Run ``is_valid()`` on the form and every formset, returning the AND.

    Every call is made before the short-circuit so each form/formset
    populates its own ``cleaned_data`` and renders its own errors.
    """
    results = [form.is_valid()]
    results.extend(fs.is_valid() for fs in formsets.values())
    results.extend(efs.is_valid() for efs in event_formsets)
    return all(results)


def apply_json_fields(advisory, formsets, event_formsets) -> None:
    """Assign cleaned formset data onto the advisory's JSON list fields."""
    payload = assemble_json(formsets, event_formsets)
    for field, value in payload.items():
        setattr(advisory, field, value)


_VALIDATION_EXCLUDED = {
    # Assigned by save(), workflow handlers, or unrelated to this form.
    "advisory_id",
    "created_by",
    "submitted_for_review_by",
    "submitted_for_review_at",
    "published_at",
    "review_status",
    "state",
}


def attach_validation_errors(form, advisory) -> bool:
    """Run ``full_clean`` on the model; on failure, surface errors via the form.

    Returns ``True`` if validation passed. The per-field structural
    validators in :mod:`advisories.validators` should not typically
    reject anything the formsets already accepted; this is defence in
    depth, and also catches advisory-level constraints (e.g. dismissed
    rows must have a reason).

    Fields not driven by the bundled form/formsets are excluded so
    unrelated stale state on an existing advisory doesn't block an edit.
    """
    try:
        advisory.full_clean(exclude=_VALIDATION_EXCLUDED)
    except ValidationError as exc:
        for field, errors in (exc.error_dict or {}).items():
            target = field if field in form.fields else None
            for err in errors:
                form.add_error(target, err)
        return False
    return True


def advanced_form_context(formsets, event_formsets) -> dict:
    """Context keys the OSV-fields template partial expects.

    Used by ``advisory_create`` / ``advisory_edit`` and the public
    ``intake.views.report_form`` so both surfaces render identical
    widgets (aliases, CWE search, affected packages with inner events,
    severity, references, credits).
    """
    from . import cwes as _cwes

    return {
        "formsets": formsets,
        "affected_rows": list(zip(formsets["affected"].forms, event_formsets, strict=False)),
        "empty_event_form": EventFormSet(prefix="affected-__prefix__-events").empty_form,
        "osv_ecosystems": OSV_ECOSYSTEMS,
        "ecosystem_datalist_id": ECOSYSTEM_DATALIST_ID,
        "cwe_catalog": _cwes.all_entries(),
    }
