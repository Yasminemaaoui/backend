from django.urls import path
from . import views

urlpatterns = [
    # ── Auth ──────────────────────────────────────────────────────
    path('me/',              views.me,              name='me'),
    path('login/',           views.login,           name='login'),
    path('logout/',          views.logout_view,     name='logout'),
    path('change-password/', views.change_password, name='change_password'),

    # ── Gestion des comptes (super_admin) ─────────────────────────
    path('users/',                              views.list_users,         name='list_users'),
    path('users/create/', views.create_user, name='create_user'),
    path('users/<int:user_id>/toggle-status/', views.toggle_user_status, name='toggle_user_status'),
    path('users/<int:user_id>/delete/',        views.delete_user,        name='delete_user'),
]