from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
import pyotp
from .models import CustomUser

class GenerateMFASecret(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        user.mfa_secret = pyotp.random_base32()
        user.save()
        uri = pyotp.totp.TOTP(user.mfa_secret).provisioning_uri(user.email, issuer_name="FileShareApp")
        return Response({'mfa_uri': uri})

class VerifyMFA(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user
        code = request.data.get('code')
        totp = pyotp.TOTP(user.mfa_secret)
        if totp.verify(code):
            refresh = RefreshToken.for_user(user)
            return Response({
                'access': str(refresh.access_token),
                'refresh': str(refresh),
            })
        return Response({'error': 'Invalid MFA code'}, status=400)
