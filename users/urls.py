from django.contrib.auth import views as auth_views
from django.urls import path
from . import views


urlpatterns =[
    path('login/', views.petppologin, name='login'),
    path('signup/', views.register, name='signup'),
    # path('signup/', views.makeanewid, name='signup'),
    path('mypage/', views.myreview, name='mypage'),
]