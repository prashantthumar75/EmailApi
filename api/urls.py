from django.contrib import admin
from django.urls import path, include
from django.conf.urls import url

urlpatterns = [
    path('admin/', admin.site.urls),
    path('auth/', include('dj_rest_auth.urls')),
    path('auth/registration/', include('dj_rest_auth.registration.urls')),
    path('', include('users.urls')),
    url(r'^api/login/', include('rest_social_auth.urls_token')),

    # url(r'^', include('django.contrib.auth.urls')),

    # # added by Prashant Thummar
    path(r'accounts/', include('allauth.urls')),
]