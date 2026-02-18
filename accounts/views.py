from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated ,AllowAny
from rest_framework.pagination import PageNumberPagination
from .models import User
from .serializers import UserSerializer ,RegisterSerializer ,LoginSerializer ,ChangePasswordSerializer

from rest_framework import status

from django.contrib.auth import authenticate 
from django.contrib.auth import login ,logout
# ==================== AUTHENTIFICATION ====================

@api_view(['POST'])
@permission_classes([AllowAny])
def register(request):
    """Créer un compte (seulement pour super admin)"""
    if request.user.is_authenticated and request.user.role != 'super_admin':
        return Response(
            {'error': 'Seul le super admin peut créer des comptes'},
            status=status.HTTP_403_FORBIDDEN
        )
    
    serializer = RegisterSerializer(data=request.data)
    if serializer.is_valid():
        user = serializer.save()
        return Response(
            UserSerializer(user).data,
            status=status.HTTP_201_CREATED
        )
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
@permission_classes([AllowAny])
def login(request):
    """Connexion utilisateur avec email et mot de passe"""
    # Récupérer les données
    email = request.data.get('email')
    password = request.data.get('password')
    
    # Vérifier que les champs sont présents
    if not email or not password:
        return Response(
            {'error': 'Veuillez fournir email et mot de passe'},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    try:
        # Chercher l'utilisateur par email
        user = User.objects.get(email=email)
        
        # Authentifier avec le username (car authenticate utilise username par défaut)
        user = authenticate(username=user.username, password=password)
        
        if user and user.is_active:
            # Retourner les données utilisateur sans créer de session
            return Response({
                'user': UserSerializer(user).data,
                'message': 'Connexion réussie'
            })
        else:
            return Response(
                {'error': 'Mot de passe incorrect'},
                status=status.HTTP_401_UNAUTHORIZED
            )
            
    except User.DoesNotExist:
        return Response(
            {'error': 'Aucun utilisateur trouvé avec cet email'},
            status=status.HTTP_404_NOT_FOUND
        )

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def logout(request):
    """Déconnexion"""
    logout(request)
    return Response({'message': 'Déconnexion réussie'})

# ==================== MÉTHODE 1: UTILISATEUR CONNECTÉ ====================

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def me(request):
    """Obtenir les informations de l'utilisateur connecté"""
    serializer = UserSerializer(request.user)
    return Response(serializer.data)


# ==================== MÉTHODE 2: LISTE DE TOUS LES UTILISATEURS ====================

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def user_list(request):
    """
    API endpoint qui retourne la liste de tous les utilisateurs.
    Accessible uniquement aux super admins.
    """
    # Vérifier si l'utilisateur est super admin
    if request.user.role != 'super_admin':
        return Response(
            {'error': 'Vous n\'avez pas la permission de voir cette liste'},
            status=403
        )
    
    # Récupérer tous les utilisateurs
    users = User.objects.all().order_by('-date_joined')
    
    # Pagination
    paginator = PageNumberPagination()
    paginator.page_size = 10  # 10 utilisateurs par page
    result_page = paginator.paginate_queryset(users, request)
    
    # Sérialiser
    serializer = UserSerializer(result_page, many=True)
    
    # Retourner avec métadonnées de pagination
    return paginator.get_paginated_response(serializer.data)

# ==================== MÉTHODE 3: LISTE USER DETAIL ====================

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def user_detail(request, pk):
    """
    API endpoint qui retourne les détails d'un utilisateur spécifique.
    """
    try:
        user = User.objects.get(pk=pk)
    except User.DoesNotExist:
        return Response(
            {'error': 'Utilisateur non trouvé'},
            status=status.HTTP_404_NOT_FOUND
        )
    
    # Vérifier les permissions (un utilisateur peut voir son propre profil, 
    # et les super admins peuvent voir tous les profils)
    if request.user.id != user.id and request.user.role != 'super_admin':
        return Response(
            {'error': 'Vous n\'avez pas la permission de voir ce profil'},
            status=status.HTTP_403_FORBIDDEN
        )
    
    serializer = UserSerializer(user)
    return Response(serializer.data)


# Ajoutez cette fonction dans views.py

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def change_password(request):
    """
    Permet à l'utilisateur connecté de changer son mot de passe
    """
    serializer = ChangePasswordSerializer(data=request.data, context={'request': request})
    
    if serializer.is_valid():
        user = request.user
        # Changer le mot de passe
        user.set_password(serializer.validated_data['new_password'])
        user.save()
        
        # Mettre à jour la session pour éviter la déconnexion
        from django.contrib.auth import update_session_auth_hash
        update_session_auth_hash(request, user)
        
        return Response({
            'message': 'Mot de passe changé avec succès'
        }, status=status.HTTP_200_OK)
    
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)




@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def user_delete(request, pk):
    """
    API endpoint pour supprimer un utilisateur (super admin uniquement).
    """
    if request.user.role != 'super_admin':
        return Response(
            {'error': 'Seul le super admin peut supprimer des utilisateurs'},
            status=status.HTTP_403_FORBIDDEN
        )
    
    try:
        user = User.objects.get(pk=pk)
    except User.DoesNotExist:
        return Response(
            {'error': 'Utilisateur non trouvé'},
            status=status.HTTP_404_NOT_FOUND
        )
    
    # Empêcher la suppression de son propre compte
    if request.user.id == user.id:
        return Response(
            {'error': 'Vous ne pouvez pas supprimer votre propre compte'},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    user.delete()
    return Response(
        {'message': 'Utilisateur supprimé avec succès'},
        status=status.HTTP_204_NO_CONTENT
    )