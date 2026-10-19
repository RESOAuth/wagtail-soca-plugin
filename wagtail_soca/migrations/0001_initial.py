from django.db import migrations, models


class Migration(migrations.Migration):
    initial = True
    dependencies = []
    operations = [
        migrations.CreateModel(
            name="LoginTransaction",
            fields=[
                (
                    "state_digest",
                    models.CharField(max_length=64, primary_key=True, serialize=False),
                ),
                ("browser_digest", models.CharField(max_length=64)),
                ("payload", models.TextField()),
                ("expires_at", models.DateTimeField(db_index=True)),
                ("consumed", models.BooleanField(default=False)),
            ],
        ),
    ]
