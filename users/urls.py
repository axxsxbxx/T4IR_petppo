from django.contrib.auth import views as auth_views
from django.urls import path
from . import views


urlpatterns =[
    path('login/', views.petppologin, name='login'),
    path('signup/', views.register, name='signup'),
    # path('signup/', views.makeanewid, name='signup'),
    path('mypage/', views.myreview, name='mypage'),
    path('delete/', views.delete, name='delete'),
    path('cdelete/', views.commentdelete, name="cdelete"),

    # 비밀번호 찾기
    path('recovery_pw/', views.RecoveryPwView.as_view(), name='recovery_pw'),
    path('recovery_pw/find/', views.ajax_find_pw_view, name='ajax_pw'),
    path('recovery_pw/auth/', views.auth_confirm_view, name='recovery_auth'),
    path('recovery_pw/reset/', views.auth_pw_reset_view, name='recovery_pw_reset'),
]