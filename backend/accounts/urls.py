from django.urls import path
from .views import *

urlpatterns = [
    path('authenticated', CheckAuthenticatedAPIView.as_view()),
    path('register', SignUpAPIView.as_view()),
    path('login', LoginAPIView.as_view()),
    path('csrf-token', GetCSRFTokenAPIView.as_view()),
    path('logout', LogoutAPIView.as_view())
]
