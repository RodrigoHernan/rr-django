# Generated by Django 2.0.3 on 2018-03-28 15:46

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('usuarios', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='cliente',
            name='email_confirmed',
            field=models.BooleanField(default=False),
        ),
    ]