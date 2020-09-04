from django.db.models import Avg
from django.shortcuts import render
import petppo

from reviews.models import Contents


def welcome(request):
    recommands = Contents.objects.values('location').annotate(rate_avg=Avg('rate')).order_by('-rate_avg')[0:3]
    #평점 top3 동물병원 리스트로 가져온거임
    contexts = {'recommands':recommands}
    return render(request, "index.html", contexts)
