import uuid

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("wagtail_soca", "0002_socasettings")]
    operations = [
        migrations.CreateModel(
            name="ClaimInspection",
            fields=[
                (
                    "id",
                    models.PositiveSmallIntegerField(
                        default=1, editable=False, primary_key=True, serialize=False
                    ),
                ),
                ("revision", models.UUIDField(default=uuid.uuid4, editable=False)),
                ("expires_at", models.DateTimeField()),
                ("captured_at", models.DateTimeField(blank=True, null=True)),
                ("payload", models.TextField(blank=True)),
            ],
        )
    ]
