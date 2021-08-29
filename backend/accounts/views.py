from django.http import response
from django.views.decorators.csrf import csrf_protect, ensure_csrf_cookie
from user_profile.models import UserProfile
from django.shortcuts import render
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny, IsAuthenticated
from django.contrib.auth.models import User
from django.utils.decorators import method_decorator
from django.contrib.auth import authenticate, login, logout


#checking authentication status
class CheckAuthenticatedAPIView(APIView):

    def get(self, request, format=None):
        user = self.request.user

        try:
            isAuthenticated = user.is_authenticated
            if isAuthenticated:
                return Response({'isAuthenticated': 'success'})
            else:
                return Response({'isAuthenticated': 'success'})
        except:
            return Response({'error': 'Something went wrong on authentication status'})


# signup apiview
@method_decorator(csrf_protect, name='dispatch')
class SignUpAPIView(APIView):
    permission_classes = [AllowAny]


    def post(self, request, format=None):
        data = self.request.data

        username = data['username']
        password = data['password']
        confirm_password = data['confirm_password']

        try:
            if password == confirm_password:
                #checking user exit
                if User.objects.filter(username=username).exists():
                    return Response({'error': 'UserName already exit'})
                else:
                    if len(password) < 6:
                        return Response({'error': 'password must be at least 6 characters'})
                    else:
                        user = User.objects.create_user(username=username, password=password)
                        user = User.objects.get(pk=user.id)
                        user_profile = UserProfile.objects.create(user=user, first_name='', last_name='', phone='', city='')

                        return Response({'success': 'User Created successful'})
            else:
                return Response({'error': 'password and confirm password not same'})

        except:
            return Response({'error': 'Some thing went wrong on registring account'})

#login api view
@method_decorator(csrf_protect, name='dispatch')
class LoginAPIView(APIView):
    permission_classes = [AllowAny]
    
    def post(self, request, format=None):
        data = self.request.data
        username = data['username']
        password = data['password']

        try:
            user = authenticate(username=username, password=password)
            if user is not None:
                if user.is_active:
                    login(request, user)
                    return Response({'success': 'User authenticated'})
                else:
                    return Response({'error': 'User is not active'})
            else:
                return Response({'error': 'User Credentials not valid'})

        except:
            return Response({'error': 'some thing went wrong on login'})

class LogoutAPIView(APIView):

    def post(self, request, format=None):
        try:
            logout(request)
            return Response({'success': 'Logout Successful'})
        except:
            return Response({'error': 'some thing went wrong on logout'})


# geting csrf cookies
@method_decorator(ensure_csrf_cookie, name='dispatch')
class GetCSRFTokenAPIView(APIView):
    permission_classes = [AllowAny]

    def get(self, request, format=None):
        return Response({'success': 'CSRF cookie set'})