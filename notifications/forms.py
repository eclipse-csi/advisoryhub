from django import forms

from accounts.models import CommentLevel, NotificationPreference

_INHERIT = ""
_TRISTATE_CHOICES = [
    (_INHERIT, "Use global default"),
    ("on", "Notify me"),
    ("off", "Don't notify me"),
]
_COMMENT_CHOICES = [
    (_INHERIT, "Use global default"),
    (CommentLevel.ALL.value, CommentLevel.ALL.label),
    (CommentLevel.MENTIONED.value, CommentLevel.MENTIONED.label),
]


class NotificationPreferenceForm(forms.ModelForm):
    class Meta:
        model = NotificationPreference
        fields = [
            "on_advisory_created",
            "on_advisory_submitted_for_review",
            "on_advisory_published",
            "on_publication_export_status",
            "comments_level",
        ]
        # comments_level has only two choices — render it as a segmented
        # control so both options are visible at once instead of hiding
        # one behind a dropdown.
        widgets = {"comments_level": forms.RadioSelect}


class AdvisoryNotificationPreferenceForm(forms.Form):
    """Per-advisory override form.

    Surfaces a coarse preset selector (Default / All / Digest / Custom)
    plus the fine-grained tri-state controls that only matter when the
    preset is ``custom``. :meth:`materialize` collapses the form into the
    four values the service layer stores; the preset shorthand maps
    directly to a pre-canned tuple of those values, so writing a preset
    is no different from writing Custom-with-those-values.
    """

    PRESET_DEFAULT = "default"
    PRESET_ALL = "all"
    PRESET_DIGEST = "digest"
    PRESET_CUSTOM = "custom"

    PRESET_CHOICES = [
        (PRESET_DEFAULT, "Use my global defaults"),
        (PRESET_ALL, "All activity"),
        (PRESET_DIGEST, "Key events + mentions"),
        (PRESET_CUSTOM, "Custom"),
    ]

    # Materializations: (submitted, published, export_status, comments_level).
    # ``None`` / ``""`` on either side means "inherit the global setting".
    _PRESETS: dict[str, tuple[bool | None, bool | None, bool | None, str]] = {
        PRESET_DEFAULT: (None, None, None, ""),
        PRESET_ALL: (True, True, True, CommentLevel.ALL.value),
        PRESET_DIGEST: (False, True, True, CommentLevel.MENTIONED.value),
    }

    preset = forms.ChoiceField(choices=PRESET_CHOICES, required=False)
    on_advisory_submitted_for_review = forms.ChoiceField(
        choices=_TRISTATE_CHOICES,
        required=False,
        label="Submitted for review",
    )
    on_advisory_published = forms.ChoiceField(
        choices=_TRISTATE_CHOICES,
        required=False,
        label="Published",
    )
    on_publication_export_status = forms.ChoiceField(
        choices=_TRISTATE_CHOICES,
        required=False,
        label="Publication export status",
    )
    comments_level = forms.ChoiceField(
        choices=_COMMENT_CHOICES,
        required=False,
        label="Comments",
    )

    def _tristate(self, name: str) -> bool | None:
        value = self.cleaned_data.get(name) or ""
        if value == "on":
            return True
        if value == "off":
            return False
        return None

    def materialize(self) -> dict:
        """Resolve preset + fine-grained inputs into the final values for
        :func:`notifications.services.set_advisory_preference`."""
        preset = self.cleaned_data.get("preset") or self.PRESET_DEFAULT
        if preset in self._PRESETS:
            submitted, published, export_status, comments = self._PRESETS[preset]
        else:
            submitted = self._tristate("on_advisory_submitted_for_review")
            published = self._tristate("on_advisory_published")
            export_status = self._tristate("on_publication_export_status")
            comments = self.cleaned_data.get("comments_level") or ""
        return {
            "on_advisory_submitted_for_review": submitted,
            "on_advisory_published": published,
            "on_publication_export_status": export_status,
            "comments_level": comments,
        }

    @classmethod
    def detect_preset(cls, pref) -> str:
        """Pick the preset that best describes the current row.

        Falls through to ``custom`` for any combination that doesn't match
        one of the canned presets — including partial overrides where only
        some fields diverge from global.
        """
        if pref is None:
            return cls.PRESET_DEFAULT
        snapshot = (
            pref.on_advisory_submitted_for_review,
            pref.on_advisory_published,
            pref.on_publication_export_status,
            pref.comments_level or "",
        )
        for name, values in cls._PRESETS.items():
            if snapshot == values:
                return name
        return cls.PRESET_CUSTOM

    @staticmethod
    def initial_from(pref) -> dict:
        """Build an ``initial`` dict from an existing override row (or
        ``None`` for the inherit-everything default)."""

        def _b(v: bool | None) -> str:
            if v is True:
                return "on"
            if v is False:
                return "off"
            return ""

        if pref is None:
            return {
                "on_advisory_submitted_for_review": "",
                "on_advisory_published": "",
                "on_publication_export_status": "",
                "comments_level": "",
            }
        return {
            "on_advisory_submitted_for_review": _b(pref.on_advisory_submitted_for_review),
            "on_advisory_published": _b(pref.on_advisory_published),
            "on_publication_export_status": _b(pref.on_publication_export_status),
            "comments_level": pref.comments_level or "",
        }
