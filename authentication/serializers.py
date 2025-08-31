from rest_framework import serializers
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer

User = get_user_model()

class SignupSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True) # To ensure that password is only writable and not readable

    class Meta:
        model = User
        fields = ['username', 'email', 'password']

        # Overriding the create method to handle password hashing (to not stored the password in plain text)
        def create(self, validated_data):
            user = User(
                username = validated_data['username'],
                email = validated_data['email'],
                role = "user"
            )
            user.set_password(validated_data['password'])
            user.save()
            return user
        
# Customizing the token to include user role as well
class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)
        # Adding custon claims 
        token["role"] = user.role
        return token
    
    def validate(self, attrs):
        data = super().validate(attrs)
        data['role'] = self.user.role
        return data