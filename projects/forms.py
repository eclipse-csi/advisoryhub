"""Admin forms for managing Projects and their OIDC group mapping.

The ``security_team`` foreign key on :class:`Project` points to a Django
:class:`~django.contrib.auth.models.Group`. Group names mirror the OIDC
group claim (``OIDC_GROUP_CLAIM``) — when the OIDC backend syncs claims
on login, a user's ``user.groups`` is rebuilt to match the claim list,
auto-creating unknown groups by name. So binding a project to a group
*by name* is exactly the OIDC mapping: enrolling a user in the OIDC
group on the IdP side puts them on the project's security team.
"""

from __future__ import annotations

from django import forms
from django.contrib.auth.models import Group

from .models import Project


class ProjectAdminForm(forms.ModelForm):
    security_team_group_name = forms.CharField(
        max_length=150,
        label="Security team OIDC group",
        help_text=(
            "Name of the OIDC group whose members form this project's "
            "security team. The group is created if it doesn't already exist."
        ),
    )

    class Meta:
        model = Project
        fields = [
            "slug",
            "name",
            "description",
            "homepage_url",
            "is_mature_publisher",
        ]
        widgets = {
            "description": forms.Textarea(attrs={"rows": 4}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.instance and self.instance.pk and self.instance.security_team_id:
            self.fields["security_team_group_name"].initial = self.instance.security_team.name

    def clean_security_team_group_name(self) -> str:
        name = self.cleaned_data["security_team_group_name"].strip()
        if not name:
            raise forms.ValidationError("Required.")
        return name

    def save(self, commit: bool = True) -> Project:
        group, _ = Group.objects.get_or_create(name=self.cleaned_data["security_team_group_name"])
        self.instance.security_team = group
        return super().save(commit=commit)
