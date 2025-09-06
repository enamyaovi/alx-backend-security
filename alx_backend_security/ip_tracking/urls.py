from django.urls import path
from ip_tracking import views as v

urlpatterns = [
    path('login/', v.loginview, name='login'),
    path('secured/', v.secure, name='secure')
]