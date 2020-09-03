from django.db import models

# Create your models here.

class Address(models.Model):
    address = models.CharField(max_length=50, primary_key=True)

class Members(models.Model):
    email = models.EmailField(primary_key=True)
    name = models.CharField(max_length=5)
    password = models.CharField(max_length=12)
    nickname = models.CharField(max_length=10)
    addr = models.ForeignKey(Address, on_delete=models.SET_NULL, null=True)
    kind = models.CharField(max_length=20, null=True)
    petage = models.IntegerField(null=True)
    petgender = models.CharField(max_length=5, null=True)
    registertime = models.DateTimeField(auto_now_add=True)
