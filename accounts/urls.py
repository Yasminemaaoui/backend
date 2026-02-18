from django.urls import path
from . import views

urlpatterns =[
    
    path('me/', views.me, name='me'),
    path('users/', views.user_list, name='user-list'),
    path('users/<int:pk>/', views.user_detail, name='user-detail'),
    path('register/', views.register, name='register'),
    path('login/', views.login, name='login'),
    path('logout/', views.logout, name='logout'),
    path('change/', views.change_password, name='change'),
    path('delete/<int:pk>/', views.user_delete, name='delete'), 
]