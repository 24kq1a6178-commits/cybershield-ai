from django.urls import path
from . import views

app_name = 'scanner'
urlpatterns = [
    path('url/', views.scan_url, name='scan_url'),
    path('message/', views.scan_message, name='scan_message'),
    path('password/', views.check_password, name='check_password'),
    path('result/<int:pk>/', views.result, name='result'),
    path('history/', views.history, name='history'),
]