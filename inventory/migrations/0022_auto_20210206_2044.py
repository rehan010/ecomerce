# Generated by Django 3.1.4 on 2021-02-06 17:44

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('inventory', '0021_auto_20210204_0907'),
    ]

    operations = [
        migrations.AlterField(
            model_name='bannerad',
            name='product',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='banner_ad', to='inventory.product'),
        ),
    ]