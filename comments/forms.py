from django import forms

from .models import AdvisoryComment


class CommentForm(forms.ModelForm):
    # Not in ``Meta.fields`` on purpose: the view reads the cleaned value
    # and passes it explicitly to ``services.add_comment``, so a crafted
    # POST that includes extra model fields can never persist this flag
    # directly via ``form.save()``.
    is_internal = forms.BooleanField(required=False, label="Internal")

    class Meta:
        model = AdvisoryComment
        fields = ["body"]
        widgets = {"body": forms.Textarea(attrs={"rows": 4, "placeholder": "Write a comment…"})}


class CommentEditForm(forms.ModelForm):
    class Meta:
        model = AdvisoryComment
        fields = ["body"]
        widgets = {"body": forms.Textarea(attrs={"rows": 4})}
