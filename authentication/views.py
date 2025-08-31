from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from .permissions import IsAdmin, IsUser  # will be in use after we've implemented user roles 
from rest_framework_simplejwt.views import TokenObtainPairView
from.serializers import SignupSerializer, CustomTokenObtainPairSerializer
    
class SignupView(APIView):
    def post(self, request):
        serializer = SignupSerializer(data = request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({
                "message": "User created successfully"
            }, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
class LoginView(TokenObtainPairView):
    serializer_class = CustomTokenObtainPairSerializer