from django.urls import path
from . import views

urlpatterns =[
    path('location/', views.findlocation, name='location'),
    path('symptom/', views.findsymptom, name='symptom'),
    path('<int:id>/', views.showreview, name='review'),
    path('write/', views.writereview, name='write'),
    path('commentwrite/', views.writecomment, name='witecomment'),
    path('mapsearch/', views.mapsearch, name='mapsearch'),
    path("search1/<location>", views.search1, name="search1"),
    ]