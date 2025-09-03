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
        
# Customizing the token to include user role as well, also overriding the validate method to allow frontend to send username or email instead of just username
class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    username_field = 'username_or_email'

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Replace default "username" field with "username_or_email"
        self.fields[self.username_field] = serializers.CharField()
        self.fields["password"] = serializers.CharField(write_only=True)

    def validate(self, attrs):
        username_or_email = attrs.get('username_or_email')
        password = attrs.get('password')

        # Try to find user by username first 
        user = User.objects.filter(username=username_or_email).first()

        # If not found, try email
        if user is None:
            user = User.objects.filter(email=username_or_email).first()

        if user is None:
            raise serializers.ValidationError({"detail": "Invalid credentials"})

        # Call parent with actual username (to generate JWT properly), backend still needs username field
        data = super().validate({
            self.username_field: user.username,
            'password': password
        })

        # Add role to response
        data["role"] = user.role
        return data 
    
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)
        # Adding custon claims 
        token["role"] = user.role
        return token