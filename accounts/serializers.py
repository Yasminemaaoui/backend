from rest_framework import serializers
from django.contrib.auth import authenticate
from .models import User

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = '__all__'  # ✅ Tous les champs du modèle User
        read_only_fields = ['id', 'email_verified', 'created_at', 'updated_at']


class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)
    
    class Meta:
        model = User
        fields = ('username', 'email', 'password', 'first_name', 'last_name', 'role', 'phone')
    
    def create(self, validated_data):
        user = User.objects.create_user(
            username=validated_data['username'],
            email=validated_data['email'],
            password=validated_data['password'],
            first_name=validated_data.get('first_name', ''),
            last_name=validated_data.get('last_name', ''),
            role=validated_data.get('role', 'etudiant'),
            phone=validated_data.get('phone', '')
        )
        return user
    
class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)
    
    def validate(self, data):
        email = data.get('email')
        password = data.get('password')
        
        try:
            # Chercher l'utilisateur par email
            user = User.objects.get(email=email)
            
            # Authentifier avec le username
            user = authenticate(username=user.username, password=password)
            
            if user and user.is_active:
                return user
            else:
                raise serializers.ValidationError("Email ou mot de passe incorrect")
                
        except User.DoesNotExist:
            raise serializers.ValidationError("Email ou mot de passe incorrect")
        

# Ajoutez cette classe dans serializers.py

class ChangePasswordSerializer(serializers.Serializer):
    """
    Sérializer pour le changement de mot de passe
    """
    old_password = serializers.CharField(write_only=True, required=True)
    new_password = serializers.CharField(write_only=True, required=True)
    confirm_password = serializers.CharField(write_only=True, required=True)

    def validate_old_password(self, value):
        user = self.context['request'].user
        if not user.check_password(value):
            raise serializers.ValidationError("L'ancien mot de passe est incorrect")
        return value

    def validate(self, data):
        if data['new_password'] != data['confirm_password']:
            raise serializers.ValidationError({
                "confirm_password": "Les nouveaux mots de passe ne correspondent pas"
            })
        
        # Vous pouvez ajouter des validations supplémentaires pour le nouveau mot de passe
        if len(data['new_password']) < 8:
            raise serializers.ValidationError({
                "new_password": "Le mot de passe doit contenir au moins 8 caractères"
            })
            
        return data
    

