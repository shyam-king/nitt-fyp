# Generated by Django 4.0.4 on 2022-04-16 22:22

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('blockchain', '0001_initial'),
    ]

    operations = [
        migrations.RenameField(
            model_name='blockkey',
            old_name='block_id',
            new_name='block',
        ),
    ]