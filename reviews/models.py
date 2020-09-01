from django.db import models

from users.models import Members

class Symptom(models.Model):
    symptom = models.CharField(primary_key= True, max_length=20)


class Contents(models.Model):
    symp = models.ForeignKey(Symptom, on_delete=models.CASCADE)
    location = models.CharField(max_length=20)
    receipt = models.FileField(blank=True, upload_to="media/photo_%Y_%m_%d")
    content = models.TextField()
    title = models.CharField(max_length=20)
    nickname = models.ForeignKey(Members, on_delete=models.CASCADE)
    writedate = models.DateTimeField(auto_now_add=True)
    recommend = models.IntegerField(default=0)
    rate = models.IntegerField()
    visitdate = models.DateTimeField()

class Comments(models.Model):
    nickname = models.ForeignKey(Members, on_delete=models.CASCADE)
    commentdate = models.DateTimeField(auto_now=True)
    commenttext = models.TextField()
    contentsnumber = models.ForeignKey(Contents, on_delete=models.CASCADE)



# Create your models here.
