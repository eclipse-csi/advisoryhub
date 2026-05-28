"""Drop AdvisoryComment.parent and its index.

Threaded replies have been removed; comments are now a flat list. Existing
reply rows survive — dropping the column promotes them to top-level
comments without touching their body, author, version history, or
``created_at`` position in the timeline.
"""

from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [
        ("comments", "0004_commentversion"),
    ]

    operations = [
        migrations.RemoveIndex(
            model_name="advisorycomment",
            name="comments_ad_parent__dc9006_idx",
        ),
        migrations.RemoveField(
            model_name="advisorycomment",
            name="parent",
        ),
    ]
