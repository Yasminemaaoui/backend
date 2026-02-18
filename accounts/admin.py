from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import User # ✅ Importer User

class CustomUserAdmin(UserAdmin):
    list_display = ('username', 'email', 'first_name', 'last_name', 'role', 'email_verified')
    list_filter = ('role', 'email_verified')
    fieldsets = UserAdmin.fieldsets + (
        ('Informations supplémentaires', {
            'fields': ('role', 'phone', 'email_verified')
        }),
    )
    add_fieldsets = UserAdmin.add_fieldsets + (
        ('Informations supplémentaires', {
            'fields': ('role', 'phone')
        }),
    )

admin.site.register(User, CustomUserAdmin)  # ✅ Maintenant User est défini
