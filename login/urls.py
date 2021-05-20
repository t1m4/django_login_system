from django.contrib import admin
from django.urls import path

from login import auth_views

urlpatterns = [
    path('', auth_views.IndexView.as_view(), name='login-index'),
    path('accounts/async_login/', auth_views.MyLoginView.as_view(), name='login-async_login'),
]
