from django.urls import path
from . import views

urlpatterns =[
    path('location/', views.findlocation, name='location'),
    path('symptom/', views.findsymptom, name='symptom'),
    path('<int:id>/', views.showreview, name='review'),
    path('write/', views.writereview, name='write'),
    path('commentwrite/', views.writecomment, name='witecomment'),
    path("search1/<location>", views.search1, name="search1"),
    path("search2/", views.searchpart, name="search"),
    path("search2/<location>", views.search2, name="search2"),
    path("heart/<int:id>/", views.heart, name="heart"),
    ]