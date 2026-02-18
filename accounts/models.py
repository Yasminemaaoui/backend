from django.contrib.auth.models import AbstractUser
from django.db import models

class User(AbstractUser):
    ROLE_CHOICES = (
        ('super_admin', 'Super Administrateur'),
        ('responsable', 'Responsable Pédagogique'),
        ('assistante', 'Assistante'),
        ('entreprise', 'Entreprise Partenaire'),
        ('formateur', 'Formateur'),
        ('etudiant', 'Étudiant'),
    )
    
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default='etudiant')
    phone = models.CharField(max_length=20, blank=True)
    email_verified = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    # ✅ AJOUTEZ CES LIGNES pour résoudre le conflit
    groups = models.ManyToManyField(
        'auth.Group',
        related_name='custom_user_set',
        blank=True,
        verbose_name='groups',
        help_text='The groups this user belongs to.'
    )
    user_permissions = models.ManyToManyField(
        'auth.Permission',
        related_name='custom_user_set',
        blank=True,
        verbose_name='user permissions',
        help_text='Specific permissions for this user.'
    )
    
    def __str__(self):
        return f"{self.username} - {self.get_role_display()}"
    
    class Meta:
        db_table = 'users'