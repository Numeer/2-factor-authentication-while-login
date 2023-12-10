from pyexpat.errors import messages
from django.shortcuts import render
from rest_framework.response import Response
from rest_framework import status, generics
from django.contrib.auth import authenticate
from otp_app.serializers import UserSerializer
from otp_app.models import UserModel
import pyotp


class RegisterView(generics.GenericAPIView):
    serializer_class = UserSerializer
    queryset = UserModel.objects.all()

    def get(self , request):
        return render(request, 'register.html')
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            try:
                serializer.save()
                return render(request, 'login.html',{'error': "Registered successfully,Please Login"}, status=status.HTTP_201_CREATED)
            except:
                return render(request, 'register.html',{"status": "fail", "error": "User with that email already exists"}, status=status.HTTP_409_CONFLICT)
        else:
            return render(request, 'register.html',{"status": "fail", "error": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)


class LoginView(generics.GenericAPIView):
    serializer_class = UserSerializer
    queryset = UserModel.objects.all()
    def get(self , request):
        return render(request, 'login.html')
    def post(self, request):
        data = request.data
        email = data.get('email')
        password = data.get('password')

        user = authenticate(username=email.lower(), password=password)

        if user is None or not user.check_password(password):
            return render(request, 'login.html', {'error': "Incorrect email or password" })

        serializer = self.serializer_class(user)
        return render(request, 'login.html', {"status": "success", "email": email,"user_id": user.id , "error":"Login Successfull", "user": serializer.data})


class GenerateOTP(generics.GenericAPIView):
    serializer_class = UserSerializer
    queryset = UserModel.objects.all()
    def post(self, request):
        data = request.data
        user_id = data.get('user_id', None)
        email = data.get('email', None)

        user = UserModel.objects.filter(id=user_id).first()
        if user == None:
            return render(request, 'login.html',{"status": "fail", "error": f"No user with Id: {user_id} found"}, status=status.HTTP_404_NOT_FOUND)

        otp_base32 = pyotp.random_base32()
        otp_auth_url = pyotp.totp.TOTP(otp_base32).provisioning_uri(
            name=email.lower(), issuer_name="codevoweb.com")

        user.otp_auth_url = otp_auth_url
        user.otp_base32 = otp_base32
        user.save()

        return render(request, 'verify_otp.html',{'code': otp_base32, 'code2': user.id , "message" : "Copy the following Code and put this on Google Authenticator with Account Name Codevoweb ", "otpauth_url": otp_auth_url})


class VerifyOTP(generics.GenericAPIView):
    serializer_class = UserSerializer
    queryset = UserModel.objects.all()
    def get(self , request):
        return render(request, 'verify_otp.html')
    def post(self, request):
        message = "Token is invalid or user doesn't exist"
        data = request.data
        user_id = data.get('user_id', None)
        otp_token = data.get('token', None)
        user = UserModel.objects.filter(id=user_id).first()
        if user == None:
            return render(request, 'verify_otp.html',{"status": "fail", "error": f"No user with Id: {user_id} found"}, status=status.HTTP_404_NOT_FOUND)

        totp = pyotp.TOTP(user.otp_base32)
        if not totp.verify(otp_token):
            return render(request, 'verify_otp.html',{"status": "fail", "error": message}, status=status.HTTP_400_BAD_REQUEST)
        user.otp_enabled = True
        user.otp_verified = True
        user.save()
        serializer = self.serializer_class(user)

        return render(request, 'validate_otp.html',{'otp_verified': True, "code": user.id, "error": "Verified Successfully Please Validate", "user": serializer.data})


class ValidateOTP(generics.GenericAPIView):
    serializer_class = UserSerializer
    queryset = UserModel.objects.all()
    def get(self , request):
        return render(request, 'validate_otp.html')
    def post(self, request):
        message = "Token is invalid or user doesn't exist"
        data = request.data
        user_id = data.get('user_id', None)
        otp_token = data.get('token', None)
        user = UserModel.objects.filter(id=user_id).first()
        if user == None:
            return render(request, 'validate_otp.html',{"status": "fail", "error": f"No user with Id: {user_id} found Generate Otp First"}, status=status.HTTP_404_NOT_FOUND)

        if not user.otp_verified:
            return render(request, 'validate_otp.html',{"status": "fail", "error": "OTP must be verified first"}, status=status.HTTP_404_NOT_FOUND)

        totp = pyotp.TOTP(user.otp_base32)
        if not totp.verify(otp_token, valid_window=1):
            return render(request, 'validate_otp.html',{"status": "fail", "error": message}, status=status.HTTP_400_BAD_REQUEST)

        return render(request, 'validate_otp.html',{'otp_valid': True, "error" : "OTP Validated Successfully"})


class DisableOTP(generics.GenericAPIView):
    serializer_class = UserSerializer
    queryset = UserModel.objects.all()
    def get(self , request):
        return render(request, 'disable.html')
    def post(self, request):
        data = request.data
        user_id = data.get('user_id', None)

        user = UserModel.objects.filter(id=user_id).first()
        if user == None:
            return Response({"status": "fail", "message": f"No user with Id: {user_id} found"}, status=status.HTTP_404_NOT_FOUND)

        user.otp_enabled = False
        user.otp_verified = False
        user.otp_base32 = None
        user.otp_auth_url = None
        user.save()
        serializer = self.serializer_class(user)

        return Response({'otp_disabled': True, 'user': serializer.data})
