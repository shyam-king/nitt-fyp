# Generated by Django 4.0.4 on 2022-04-17 09:01

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('blockchain', '0004_alter_block_block_id'),
    ]

    operations = [
        migrations.AddField(
            model_name='block',
            name='prev_block_hash',
            field=models.TextField(null=True),
        ),
        migrations.AddField(
            model_name='block',
            name='prev_block_id',
            field=models.CharField(max_length=255, null=True),
        ),
    ]
