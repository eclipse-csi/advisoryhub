"""Forms for the admin console."""

from __future__ import annotations

from django import forms

from .models import MaintenanceMode


class MaintenanceModeForm(forms.ModelForm):
    """Toggle maintenance mode and set the banner message in one POST."""

    class Meta:
        model = MaintenanceMode
        fields = ["is_enabled", "message"]
        widgets = {
            # Rendered as a CSS toggle switch (.switch in advisoryhub.css);
            # role="switch" makes assistive tech announce on/off, not "checked".
            "is_enabled": forms.CheckboxInput(attrs={"class": "switch__input", "role": "switch"}),
            "message": forms.Textarea(
                attrs={
                    "rows": 3,
                    "placeholder": (
                        "e.g. AdvisoryHub is paused for scheduled maintenance "
                        "until 14:00 UTC. Vulnerability reports are temporarily "
                        "unavailable."
                    ),
                }
            ),
        }
        labels = {
            "is_enabled": "Maintenance mode",
            "message": "Message shown to paused users",
        }

    def clean_message(self) -> str:
        # Normalise whitespace; the banner default kicks in for an empty value.
        return (self.cleaned_data.get("message") or "").strip()
