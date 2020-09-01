from django.shortcuts import render
import petppo

from reviews.models import Contents


def welcome(request):
    return render(request, "index.html")


# Create your views here.
