from django.urls import path, re_path
from django.views.generic import TemplateView
from allauth.account.views import ConfirmEmailView



from django.conf.urls import url

from .views import *
from rest_framework_simplejwt.views import (
    TokenRefreshView,
)

urlpatterns = [
    # path('login/', )
    # path('register/', RegisterView.as_view(), name='rest_register'),
    # path('verify-email/', VerifyEmailView.as_view(), name='rest_verify_email'),

    url(r'^rest-auth/registration/account-confirm-email/(?P<key>[-:\w]+)/$', ConfirmEmailView.as_view(),
        name='account_confirm_email'),
    re_path(r'^rest-auth/registration/account-email-verification-sent/', ConfirmEmailView.as_view(),
        name='account_email_verification_sent'),


    url('password/reset/', PasswordResetView.as_view(), name='rest_password_reset'),

    url(r'^password_reset/confirm/(?P<uidb64>[0-9A-Za-z_\-]+)/(?P<token>[0-9A-Za-z]{1,13}-[0-9A-Za-z]{1,20})/$',
        PasswordResetConfirmView.as_view(), name='password_reset_confirm'),

    # URLs that require a user to be logged in with a valid session / token.
    # path('logout/', LogoutView.as_view(), name='rest_logout'),
    # path('user/', UserDetailsView.as_view(), name='rest_user_details'),
    path('password/change/', PasswordChangeView.as_view(), name='rest_password_change'),
    path('facebook/', FacebookConnect.as_view(), name='fb_login'),
    # path('dj-rest-auth/google/', GoogleLogin.as_view(), name='google_login'),
    # path('google/', GoogleOauth, name='google_login'),
    path('google/', GoogleLogin.as_view(), name='google_login'),
    # path('facebook/connection', FacebookConnect.as_view(), name='fb_connect'),
    path('', index),
    path('show/', SocialAccountListView.as_view()),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),

]
