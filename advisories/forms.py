"""Forms for advisory authoring.

The advisory form is broken into the same logical sections as GitHub
Security Advisories — summary, identifiers, affected products, severity,
references, credits, detailed description.

The six list-shaped fields (``aliases``, ``cwe_ids``, ``references``,
``severity``, ``credits``, ``affected``) are not directly part of
:class:`AdvisoryForm` — they are rendered and validated by per-item
:mod:`django.forms.formsets` so authors get a structured UI instead of
raw JSON. The view assembles the cleaned formset data back into JSON
lists and assigns them to the model before saving.
"""

from __future__ import annotations

from django import forms
from django.core.exceptions import ValidationError
from django.forms import BaseFormSet, formset_factory

from .models import Advisory

# Choice constants — mirror the enums in advisories/validators.py and the
# vendored OSV schema at publication/schemas/osv.upstream.json.
REFERENCE_TYPES = [
    ("ADVISORY", "Advisory"),
    ("ARTICLE", "Article"),
    ("DETECTION", "Detection"),
    ("DISCUSSION", "Discussion"),
    ("REPORT", "Report"),
    ("FIX", "Fix"),
    ("INTRODUCED", "Introduced"),
    ("GIT", "Git"),
    ("PACKAGE", "Package"),
    ("EVIDENCE", "Evidence"),
    ("WEB", "Web"),
]

SEVERITY_TYPES = [
    ("CVSS_V3", "CVSS v3"),
    ("CVSS_V4", "CVSS v4"),
    ("CVSS_V2", "CVSS v2"),
    ("Ubuntu", "Ubuntu"),
]

# Ubuntu severity scores form a closed enum per the OSV schema; CVSS scores
# are free-form vector strings checked by the schema validator at publish time.
UBUNTU_SCORES = [
    ("negligible", "negligible"),
    ("low", "low"),
    ("medium", "medium"),
    ("high", "high"),
    ("critical", "critical"),
]
UBUNTU_SEVERITY_TYPE = "Ubuntu"

# --- Self-describing OSV enums ------------------------------------------------
#
# Submitted values must be the verbatim upstream identifiers (OSV JSON copies
# them straight through); only the *display* label is softened for the UI.
# Descriptions are paraphrased from the OSV schema spec
# (https://ossf.github.io/osv-schema/) and surface as both a native
# <option title> tooltip and a contextual hint next to the select. The hint
# wiring lives in static/advisoryhub-formsets.js and looks for selects with
# `data-describing` plus a sibling `<small data-describing-help>` element
# within an ancestor marked `data-describing-row`.


class DescribingSelect(forms.Select):
    """Select that exposes a per-value description as the option's ``title``."""

    def __init__(self, descriptions, attrs=None, choices=()):
        merged = {"data-describing": ""}
        if attrs:
            merged.update(attrs)
        super().__init__(attrs=merged, choices=choices)
        self._descriptions = descriptions

    def create_option(self, name, value, label, selected, index, subindex=None, attrs=None):
        option = super().create_option(
            name, value, label, selected, index, subindex=subindex, attrs=attrs
        )
        desc = self._descriptions.get(str(value))
        if desc:
            option["attrs"]["title"] = desc
        return option


RANGE_TYPE_DESCRIPTIONS: dict[str, str] = {
    "SEMVER": "Versions follow SemVer 2.0 ordering (e.g. 1.2.3, 2.0.0-rc.1).",
    "ECOSYSTEM": "Versions are ordered by the package ecosystem's native scheme (npm, PyPI, Maven, …).",
    "GIT": "Versions are full-length Git commit SHAs; a repository URL is required.",
}
RANGE_TYPES = [
    ("", "—"),
    ("SEMVER", "SemVer"),
    ("ECOSYSTEM", "Ecosystem"),
    ("GIT", "Git"),
]


# OSV affected.ranges[].events kinds. Submitted values are used as the JSON
# *key* in the OSV ranges output (see advisories/form_assembly.py), so they
# must remain the lowercase upstream identifiers; only the display label is
# softened.
EVENT_KIND_DESCRIPTIONS: dict[str, str] = {
    "introduced": "Version where the vulnerability was introduced (required; at least one per range).",
    "fixed": "Version where the vulnerability was fixed.",
    "last_affected": "Last version still affected — mutually exclusive with 'fixed'.",
    "limit": "Upper bound where the range stops being considered; rarely used outside Git ranges.",
}
EVENT_KINDS = [
    ("introduced", "Introduced"),
    ("fixed", "Fixed"),
    ("last_affected", "Last affected"),
    ("limit", "Limit"),
]


# OSV severity.type enum. CVSS_* take a vector string; "Ubuntu" takes the
# qualitative score from UBUNTU_SCORES (toggle handled by SeverityForm).
SEVERITY_TYPE_DESCRIPTIONS: dict[str, str] = {
    "CVSS_V3": "CVSS v3.x vector string, e.g. CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H.",
    "CVSS_V4": "CVSS v4.0 vector string, e.g. CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N.",
    "CVSS_V2": "Legacy CVSS v2 vector string; rarely used today.",
    "Ubuntu": "Ubuntu's qualitative severity rating (negligible / low / medium / high / critical).",
}


# OSV references.type enum — see https://ossf.github.io/osv-schema/#referencestype-field.
REFERENCE_TYPE_DESCRIPTIONS: dict[str, str] = {
    "ADVISORY": "A published security advisory for the vulnerability.",
    "ARTICLE": "An article or blog post describing the vulnerability.",
    "DETECTION": "A tool, signature, or technique to detect the vulnerability.",
    "DISCUSSION": "A social-media post, mailing list, or issue thread discussing the vulnerability.",
    "REPORT": "A bug or issue-tracker report of the vulnerability.",
    "FIX": "A source-code change (commit, PR, patch) that addresses the vulnerability.",
    "INTRODUCED": "A source-code change that introduced the vulnerability.",
    "GIT": "A web page of the project's source repository.",
    "PACKAGE": "A web page for the affected package.",
    "EVIDENCE": "A demonstration of the vulnerability (e.g. proof-of-concept).",
    "WEB": "A web page of some other kind; use when no more specific type fits.",
}


# OSV credits.type enum — see https://ossf.github.io/osv-schema/#creditstype-field.
CREDIT_TYPE_DESCRIPTIONS: dict[str, str] = {
    "FINDER": "Identified the vulnerability.",
    "REPORTER": "Notified the vendor or a CNA of the vulnerability.",
    "ANALYST": "Validated the vulnerability for accuracy or severity.",
    "COORDINATOR": "Facilitated the coordinated-disclosure response process.",
    "REMEDIATION_DEVELOPER": "Prepared a code change or other remediation.",
    "REMEDIATION_REVIEWER": "Reviewed remediation plans for completeness and accuracy.",
    "REMEDIATION_VERIFIER": "Verified the effectiveness of the remediation.",
    "TOOL": "A tool or automated system that improved processing of the vulnerability.",
    "SPONSOR": "Funded or otherwise supported the work on this vulnerability.",
    "OTHER": "Anything not covered by the other types.",
}
CREDIT_TYPES = [
    ("", "—"),
    ("FINDER", "Finder"),
    ("REPORTER", "Reporter"),
    ("ANALYST", "Analyst"),
    ("COORDINATOR", "Coordinator"),
    ("REMEDIATION_DEVELOPER", "Remediation developer"),
    ("REMEDIATION_REVIEWER", "Remediation reviewer"),
    ("REMEDIATION_VERIFIER", "Remediation verifier"),
    ("TOOL", "Tool"),
    ("SPONSOR", "Sponsor"),
    ("OTHER", "Other"),
]

# Canonical OSV ecosystem list (from the schema's pattern). Used to power
# a <datalist> on the package_ecosystem input — authors get autocomplete
# but can still type free text for variants like ``Debian:11``.
OSV_ECOSYSTEMS = [
    "AlmaLinux",
    "Alpaquita",
    "Alpine",
    "Android",
    "Azure Linux",
    "BellSoft Hardened Containers",
    "Bioconductor",
    "Bitnami",
    "Chainguard",
    "CleanStart",
    "ConanCenter",
    "CRAN",
    "crates.io",
    "Debian",
    "Docker Hardened Images",
    "Echo",
    "FreeBSD",
    "GHC",
    "GitHub Actions",
    "Go",
    "Hackage",
    "Hex",
    "Julia",
    "Kubernetes",
    "Linux",
    "Mageia",
    "Maven",
    "MinimOS",
    "npm",
    "NuGet",
    "opam",
    "openEuler",
    "openSUSE",
    "OSS-Fuzz",
    "Packagist",
    "Photon OS",
    "Pub",
    "PyPI",
    "Red Hat",
    "Rocky Linux",
    "Root",
    "RubyGems",
    "SUSE",
    "SwiftURL",
    "TuxCare",
    "Ubuntu",
    "VSCode",
    "Wolfi",
    "GIT",
]
ECOSYSTEM_DATALIST_ID = "osv-ecosystems"


# ---------------------------------------------------------------------------
# Per-item sub-forms
# ---------------------------------------------------------------------------


class AliasForm(forms.Form):
    value = forms.CharField(label="Alias", max_length=200, strip=True)


class CweIdForm(forms.Form):
    # Rendered as a hidden input — it carries the canonical "CWE-NN" value
    # that gets posted and stored. A sibling visible search input (added in
    # templates/advisories/form.html) is driven by static/advisoryhub-cwe.js
    # and shows "CWE-NN — Name" for human readability. The two are kept in
    # sync by the JS; the catalog is injected once per form via json_script.
    value = forms.CharField(
        label="CWE",
        max_length=32,
        strip=True,
        widget=forms.HiddenInput(attrs={"data-cwe-hidden": ""}),
    )

    def clean_value(self) -> str:
        from .cwes import is_known

        value = (self.cleaned_data["value"] or "").strip().upper()
        if not value.startswith("CWE-"):
            raise forms.ValidationError("CWE id must start with 'CWE-'.")
        if not is_known(value):
            raise forms.ValidationError(f"{value} is not a recognised CWE identifier.")
        return value


class ReferenceForm(forms.Form):
    type = forms.ChoiceField(
        choices=REFERENCE_TYPES,
        initial="WEB",
        widget=DescribingSelect(REFERENCE_TYPE_DESCRIPTIONS),
    )
    url = forms.URLField(max_length=2000, assume_scheme="https")


class SeverityForm(forms.Form):
    """Per-row severity.

    The OSV schema constrains the ``score`` differently depending on
    ``type``: CVSS_V2/V3/V4 use vector strings (regex-checked at publish
    time); Ubuntu uses a closed enum. We expose two inputs and pick the
    right one in :meth:`clean`. The JS in
    ``static/advisoryhub-formsets.js`` toggles which one is visible.
    """

    type = forms.ChoiceField(
        choices=SEVERITY_TYPES,
        initial="CVSS_V3",
        widget=DescribingSelect(SEVERITY_TYPE_DESCRIPTIONS, attrs={"data-severity-type": ""}),
    )
    score = forms.CharField(
        max_length=200,
        required=False,
        strip=True,
        widget=forms.TextInput(attrs={"data-severity-score": "cvss"}),
    )
    score_ubuntu = forms.ChoiceField(
        choices=[("", "—"), *UBUNTU_SCORES],
        required=False,
        widget=forms.Select(attrs={"data-severity-score": "ubuntu"}),
    )

    def clean(self) -> dict:
        cd = super().clean() or {}
        stype = cd.get("type")
        if stype == UBUNTU_SEVERITY_TYPE:
            ubuntu = cd.get("score_ubuntu") or ""
            if not ubuntu:
                self.add_error("score_ubuntu", "Ubuntu severity requires a score.")
            cd["score"] = ubuntu
        else:
            if not (cd.get("score") or "").strip():
                self.add_error("score", "Score is required.")
            cd["score_ubuntu"] = ""
        return cd


class CreditForm(forms.Form):
    name = forms.CharField(max_length=200, strip=True)
    type = forms.ChoiceField(
        choices=CREDIT_TYPES,
        required=False,
        widget=DescribingSelect(CREDIT_TYPE_DESCRIPTIONS),
    )


class EventForm(forms.Form):
    kind = forms.ChoiceField(
        choices=EVENT_KINDS,
        initial="introduced",
        widget=DescribingSelect(EVENT_KIND_DESCRIPTIONS),
    )
    value = forms.CharField(max_length=200, strip=True)


class BaseEventFormSet(BaseFormSet):
    """Enforce OSV per-range event constraints next to the offending range.

    The same rules live in :func:`advisories.validators.validate_affected`
    as the model-level safety net; this formset-level ``clean`` exists so
    errors render as ``non_form_errors`` inside the events fieldset instead
    of a single generic ``affected`` field error far from the row.
    """

    def clean(self) -> None:
        super().clean()
        if any(self.errors):
            # Per-row errors already surfaced; skip cross-row checks so we
            # don't pile up duplicate complaints on top of field errors.
            return
        kinds: list[str] = []
        for form in self.forms:
            if not hasattr(form, "cleaned_data"):
                continue
            cd = form.cleaned_data
            if not cd or cd.get("DELETE"):
                continue
            kind = cd.get("kind")
            if kind:
                kinds.append(kind)
        if not kinds:
            # No events at all — the range is either empty or being deleted
            # via its outer row. ``validate_affected`` handles the "range
            # with no events" case for ranges that do reach the model.
            return
        errors: list[str] = []
        if "introduced" not in kinds:
            errors.append("At least one 'Introduced' event is required for this range.")
        if "fixed" in kinds and "last_affected" in kinds:
            errors.append(
                "A range cannot have both 'Fixed' and 'Last affected' events — "
                "they are mutually exclusive."
            )
        if errors:
            raise ValidationError(errors)


class AffectedForm(forms.Form):
    package_name = forms.CharField(label="Package name", max_length=200, strip=True)
    package_ecosystem = forms.CharField(
        label="Ecosystem",
        max_length=64,
        required=False,
        strip=True,
        # The list of supported OSV ecosystems is open-ended (variants like
        # ``Debian:11`` are valid). Free text with a <datalist> for
        # autocomplete keeps both common picks and extensions easy.
        widget=forms.TextInput(attrs={"list": ECOSYSTEM_DATALIST_ID}),
    )
    package_purl = forms.CharField(
        label="Package URL (purl)",
        max_length=500,
        required=False,
        strip=True,
        help_text="Optional purl, without the @version component, e.g. pkg:maven/org.example/lib",
    )
    range_type = forms.ChoiceField(
        label="Range type",
        choices=RANGE_TYPES,
        required=False,
        initial="ECOSYSTEM",
        widget=DescribingSelect(RANGE_TYPE_DESCRIPTIONS),
    )
    versions = forms.CharField(
        label="Versions",
        required=False,
        widget=forms.Textarea(attrs={"rows": 2}),
        help_text="Optional explicit versions, one per line.",
    )


# ---------------------------------------------------------------------------
# Formset factories
# ---------------------------------------------------------------------------


AliasFormSet = formset_factory(AliasForm, extra=0, can_delete=True, min_num=0)
CweIdFormSet = formset_factory(CweIdForm, extra=0, can_delete=True, min_num=0)
ReferenceFormSet = formset_factory(ReferenceForm, extra=0, can_delete=True, min_num=0)
SeverityFormSet = formset_factory(SeverityForm, extra=0, can_delete=True, min_num=0)
CreditFormSet = formset_factory(CreditForm, extra=0, can_delete=True, min_num=0)
EventFormSet = formset_factory(
    EventForm, formset=BaseEventFormSet, extra=0, can_delete=True, min_num=0
)
AffectedFormSet = formset_factory(AffectedForm, extra=0, can_delete=True, min_num=0)


# Section name → formset class. The view iterates this to bind, validate,
# and render each list-shaped field.
LIST_FORMSETS: dict[str, type] = {
    "aliases": AliasFormSet,
    "cwe_ids": CweIdFormSet,
    "references": ReferenceFormSet,
    "severity": SeverityFormSet,
    "credits": CreditFormSet,
    "affected": AffectedFormSet,
}


# ---------------------------------------------------------------------------
# Top-level forms
# ---------------------------------------------------------------------------


class AdvisoryForm(forms.ModelForm):
    """Form used both for creation and editing.

    The ``project`` choice is restricted by the view to projects the current
    user belongs to (see ``advisories.views.advisory_create``); never trust
    the submitted value without re-checking with the permissions service.

    The six list-shaped JSON fields (aliases, references, affected,
    severity, cwe_ids, credits) are intentionally absent here — they are
    handled by sibling formsets in the view.
    """

    class Meta:
        model = Advisory
        fields = ["project", "summary", "details"]
        widgets = {
            "summary": forms.TextInput(attrs={"size": 80}),
            "details": forms.Textarea(attrs={"rows": 10}),
        }
        help_texts = {"details": "Markdown is supported."}


class AdvisoryDismissForm(forms.Form):
    reason = forms.CharField(widget=forms.Textarea(attrs={"rows": 4}))


class GhsaLinkedAdvisoryEditForm(forms.ModelForm):
    """Edit form for GHSA-linked advisories.

    OSV-shaped fields (summary, details, aliases, references, affected,
    severity, cwe_ids, credits) are synced from the upstream GHSA on
    GitHub and rendered read-only in the detail/edit templates. The only
    field an AdvisoryHub owner can change here is the project assignment;
    everything else flows through :func:`ghsa.services.sync_single_ghsa`.
    """

    class Meta:
        model = Advisory
        fields = ["project"]
