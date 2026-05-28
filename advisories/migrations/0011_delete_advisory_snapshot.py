"""Drop the legacy ``AdvisorySnapshot`` model.

Once ``publication.0003`` and ``workflows.0008`` have re-keyed their
foreign keys to ``AdvisoryVersion``, no model references
``AdvisorySnapshot`` anymore and the table can be dropped. Edit history
lives in ``AdvisoryVersion``; rendered OSV/CSAF live in
``publication.PublicationArtifact`` keyed to the task that produced them
— the ``osv_json``/``csaf_json`` fields previously duplicated on
``AdvisorySnapshot`` go away with the table.
"""

from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [
        ("advisories", "0010_advisory_version"),
        ("publication", "0003_publicationtask_version"),
        ("workflows", "0008_reviewtask_version"),
    ]

    operations = [
        migrations.DeleteModel(name="AdvisorySnapshot"),
    ]
