# Generated by Django 4.0.4 on 2022-05-07 19:12

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('peer', '0002_riskanalysisresult'),
    ]

    operations = [
        migrations.AddField(
            model_name='auctionparticipant',
            name='pv_installment_factor',
            field=models.FloatField(null=True),
        ),
    ]
