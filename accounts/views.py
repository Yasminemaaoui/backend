from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from rest_framework import status
from django.db.models import Q
from django.contrib.auth import authenticate, login as auth_login, logout as auth_logout
from .serializers import LoginSerializer, ChangePasswordSerializer
from .models import User
import re

def is_super_admin(user):
    if not user.is_authenticated:
        return False
    if user.role == 'super_admin':
        return True
    if user.is_superuser:
        User.objects.filter(pk=user.pk).update(role='super_admin')
        user.role = 'super_admin'
        return True
    return False


# ── AUTH ──────────────────────────────────────────────────────────

@api_view(['POST'])
@permission_classes([AllowAny])
def login(request):
    email = request.data.get('email', '').strip()
    password = request.data.get('password', '')
    
    if not email:
        return Response({
            'success': False, 'error': "L'email est requis",
            'field': 'email', 'error_type': 'required'
        }, status=status.HTTP_400_BAD_REQUEST)
    
    email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(email_regex, email):
        return Response({
            'success': False, 'error': "Format d'email invalide",
            'field': 'email', 'error_type': 'invalid_format'
        }, status=status.HTTP_400_BAD_REQUEST)
    
    if not password:
        return Response({
            'success': False, 'error': 'Le mot de passe est requis',
            'field': 'password', 'error_type': 'required'
        }, status=status.HTTP_400_BAD_REQUEST)
    
    if len(password) < 3:
        return Response({
            'success': False,
            'error': 'Le mot de passe doit contenir au moins 3 caractères',
            'field': 'password', 'error_type': 'too_short'
        }, status=status.HTTP_400_BAD_REQUEST)
    
    try:
        user = User.objects.get(email=email)
        if not user.is_active:
            return Response({
                'success': False,
                'error': "Ce compte est désactivé. Contactez l'administrateur.",
                'field': 'general', 'error_type': 'inactive'
            }, status=status.HTTP_401_UNAUTHORIZED)
        
        authenticated_user = authenticate(username=user.username, password=password)
        if authenticated_user:
            auth_login(request, authenticated_user)
            return Response({
                'success': True, 'message': 'Connexion réussie',
                'user': {
                    'id': user.id, 'username': user.username,
                    'email': user.email, 'first_name': user.first_name,
                    'last_name': user.last_name, 'role': user.role, 'phone': user.phone,
                }
            }, status=status.HTTP_200_OK)
        else:
            return Response({
                'success': False, 'error': 'Mot de passe incorrect',
                'field': 'password', 'error_type': 'wrong_password'
            }, status=status.HTTP_401_UNAUTHORIZED)
            
    except User.DoesNotExist:
        return Response({
            'success': False, 'error': 'Aucun compte trouvé avec cet email',
            'field': 'email', 'error_type': 'not_found'
        }, status=status.HTTP_404_NOT_FOUND)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def logout_view(request):
    auth_logout(request)
    return Response({'success': True, 'message': 'Deconnexion reussie'}, status=status.HTTP_200_OK)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def me(request):
    user = request.user
    return Response({
        'id': user.id, 'username': user.username,
        'email': user.email, 'first_name': user.first_name,
        'last_name': user.last_name, 'role': user.role, 'phone': user.phone,
    }, status=status.HTTP_200_OK)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def change_password(request):
    serializer = ChangePasswordSerializer(data=request.data, context={'request': request})
    if serializer.is_valid():
        user = request.user
        user.set_password(serializer.validated_data['new_password'])
        user.save()
        auth_login(request, user)
        return Response({'success': True, 'message': 'Mot de passe change avec succes'}, status=status.HTTP_200_OK)
    return Response({'success': False, 'errors': serializer.errors}, status=status.HTTP_400_BAD_REQUEST)


# ── GESTION DES COMPTES ───────────────────────────────────────────

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def list_users(request):
    queryset = User.objects.all().order_by('id')

    search = request.query_params.get('search', '').strip()
    role   = request.query_params.get('role', '').strip()
    active = request.query_params.get('is_active', '').strip()

    if search:
        queryset = queryset.filter(
            Q(first_name__icontains=search) | Q(last_name__icontains=search) |
            Q(email__icontains=search)      | Q(username__icontains=search)
        )
    if role:
        queryset = queryset.filter(role=role)
    if active in ('true', 'false'):
        queryset = queryset.filter(is_active=(active == 'true'))

    data = []
    for idx, user in enumerate(queryset, start=1):
        full_name = f"{user.first_name} {user.last_name}".strip() or user.username
        initiales = (
            (user.first_name[0] + user.last_name[0]).upper()
            if user.first_name and user.last_name
            else user.username[:2].upper()
        )
        data.append({
            'id':        user.id,
            'numero':    str(idx).zfill(2),
            'code':      f'#USR-{str(user.id).zfill(3)}',
            'nom':       full_name,
            'initiales': initiales,
            'email':     user.email,
            'role':      user.role,
            'is_active': user.is_active,
        })

    return Response({
        'success': True, 'count': len(data),
        'can_manage': is_super_admin(request.user),
        'users': data,
    }, status=status.HTTP_200_OK)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def create_user(request):
    """
    Crée un nouvel utilisateur.
    Accessible uniquement au super_admin.

    Body attendu :
        first_name   (str)  – prénom
        last_name    (str)  – nom
        email        (str)  – adresse e-mail unique
        phone        (str)  – numéro de téléphone
        role         (str)  – rôle parmi les ROLE_CHOICES
        is_active    (bool) – statut actif/inactif
        password     (str)  – mot de passe (min 8 caractères)
    """
    # ── 1. Vérification des droits ────────────────────────────────
    if not is_super_admin(request.user):
        return Response(
            {'success': False, 'message': 'Accès refusé. Réservé au Super Administrateur.'},
            status=status.HTTP_403_FORBIDDEN
        )

    # ── 2. Récupération et nettoyage des données ──────────────────
    first_name = request.data.get('first_name', '').strip()
    last_name  = request.data.get('last_name',  '').strip()
    email      = request.data.get('email',      '').strip().lower()
    phone      = request.data.get('phone',      '').strip()
    role       = request.data.get('role',       '').strip()
    is_active  = request.data.get('is_active',  True)
    password   = request.data.get('password',   '')

    # Convertit is_active si envoyé en string depuis un formulaire
    if isinstance(is_active, str):
        is_active = is_active.lower() in ('true', '1', 'actif')

    # ── 3. Validations ────────────────────────────────────────────
    errors = {}

    if not first_name:
        errors['first_name'] = 'Le prénom est obligatoire.'
    elif len(first_name) < 2:
        errors['first_name'] = 'Le prénom doit contenir au moins 2 caractères.'

    if not last_name:
        errors['last_name'] = 'Le nom est obligatoire.'
    elif len(last_name) < 2:
        errors['last_name'] = 'Le nom doit contenir au moins 2 caractères.'

    email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not email:
        errors['email'] = "L'adresse e-mail est obligatoire."
    elif not re.match(email_regex, email):
        errors['email'] = "Format d'e-mail invalide."
    elif User.objects.filter(email=email).exists():
        errors['email'] = 'Un compte avec cet e-mail existe déjà.'

    valid_roles = [r[0] for r in User.ROLE_CHOICES]
    if not role:
        errors['role'] = 'Le rôle est obligatoire.'
    elif role not in valid_roles:
        errors['role'] = f'Rôle invalide. Valeurs acceptées : {", ".join(valid_roles)}.'

    if not password:
        errors['password'] = 'Le mot de passe est obligatoire.'
    elif len(password) < 8:
        errors['password'] = 'Le mot de passe doit contenir au moins 8 caractères.'

    if errors:
        return Response(
            {'success': False, 'message': 'Données invalides.', 'errors': errors},
            status=status.HTTP_400_BAD_REQUEST
        )

    # ── 4. Génération d'un username unique ────────────────────────
    base_username = re.sub(r'[^a-z0-9]', '', f"{first_name}{last_name}".lower()) or email.split('@')[0]
    username = base_username
    counter  = 1
    while User.objects.filter(username=username).exists():
        username = f"{base_username}{counter}"
        counter += 1

    # ── 5. Création de l'utilisateur ──────────────────────────────
    user = User.objects.create_user(
        username=username,
        email=email,
        password=password,
        first_name=first_name,
        last_name=last_name,
        role=role,
        phone=phone,
        is_active=is_active,
    )

    # ── 6. Réponse ────────────────────────────────────────────────
    full_name = f"{user.first_name} {user.last_name}".strip()
    return Response({
        'success': True,
        'message': f'Le compte de {full_name} a été créé avec succès.',
        'user': {
            'id':        user.id,
            'code':      f'#USR-{str(user.id).zfill(3)}',
            'nom':       full_name,
            'email':     user.email,
            'role':      user.role,
            'is_active': user.is_active,
        }
    }, status=status.HTTP_201_CREATED)


@api_view(['PATCH'])
@permission_classes([IsAuthenticated])
def toggle_user_status(request, user_id):
    if not is_super_admin(request.user):
        return Response({'success': False, 'message': 'Acces refuse.'}, status=status.HTTP_403_FORBIDDEN)
    try:
        user = User.objects.get(id=user_id)
    except User.DoesNotExist:
        return Response({'success': False, 'message': 'Utilisateur introuvable.'}, status=status.HTTP_404_NOT_FOUND)
    if user.id == request.user.id:
        return Response({'success': False, 'message': 'Vous ne pouvez pas modifier votre propre statut.'}, status=status.HTTP_400_BAD_REQUEST)
    user.is_active = not user.is_active
    user.save()
    return Response({
        'success': True,
        'message': f"Utilisateur {'active' if user.is_active else 'desactive'} avec succes.",
        'is_active': user.is_active,
    }, status=status.HTTP_200_OK)


@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def delete_user(request, user_id):
    if not is_super_admin(request.user):
        return Response({'success': False, 'message': 'Acces refuse.'}, status=status.HTTP_403_FORBIDDEN)
    try:
        user = User.objects.get(id=user_id)
    except User.DoesNotExist:
        return Response({'success': False, 'message': 'Utilisateur introuvable.'}, status=status.HTTP_404_NOT_FOUND)
    if user.id == request.user.id:
        return Response({'success': False, 'message': 'Vous ne pouvez pas supprimer votre propre compte.'}, status=status.HTTP_400_BAD_REQUEST)
    user.delete()
    return Response({'success': True, 'message': 'Utilisateur supprime avec succes.'}, status=status.HTTP_200_OK)