"""gslauth URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""

from django.contrib import admin
from django.urls import path

from gslsites.views import (index, logindotgov, logindotgov_authenticated, logout)

urlpatterns = [
    path('admin/', admin.site.urls),
    path('gslauth/logindotgov/', logindotgov, name='logindotgov'),
    path('gslauth/logindotgov_authenticated', logindotgov_authenticated, name='gslauth_logindotgov_authenticated'),
    path('gslauth/logoutdotgov', logout, name='gslauth_logoutdotgov'),
    path('gslauth/logout', logout, name='gslauth_logout'),
    path('/', index, name='index')
]
