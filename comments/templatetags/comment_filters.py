from django import template
from django.utils.safestring import mark_safe

from comments.services import render_markdown

register = template.Library()


@register.filter(name="comment_markdown")
def comment_markdown(value: str) -> str:
    """Render comment markdown to a sanitized HTML fragment."""
    return mark_safe(render_markdown(value or ""))
