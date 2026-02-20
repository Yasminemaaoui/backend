from django.urls import path
from . import views

urlpatterns = [
    path('me/', views.me, name='me'),
    path('login/', views.login, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('change-password/', views.change_password, name='change_password'),  # ✅ Nouveau
]