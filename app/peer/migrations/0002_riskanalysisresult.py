# Generated by Django 4.0.4 on 2022-05-07 18:33

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('peer', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='RiskAnalysisResult',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('alias', models.CharField(max_length=255)),
                ('risky_units', models.FloatField()),
                ('auction', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='peer.auction')),
            ],
        ),
    ]
