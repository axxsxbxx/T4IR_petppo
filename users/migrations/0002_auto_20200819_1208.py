# Generated by Django 3.1 on 2020-08-19 03:08

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='members',
            name='kind',
            field=models.CharField(max_length=20, null=True),
        ),
        migrations.AlterField(
            model_name='members',
            name='petage',
            field=models.IntegerField(null=True),
        ),
        migrations.AlterField(
            model_name='members',
            name='petgender',
            field=models.CharField(max_length=5, null=True),
        ),
        migrations.DeleteModel(
            name='Pet',
        ),
    ]
