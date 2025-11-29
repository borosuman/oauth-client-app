from django.urls import path

from . import views

app_name = "client_app"

urlpatterns = [
    path("", views.home, name="home"),
    path("login/", views.login, name="login"),
    path("callback/", views.callback, name="callback"),
    path("callback", views.callback),
    path("logout/", views.logout_view, name="logout"),
]
