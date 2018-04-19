from django.conf.urls import url
from django.urls import include, path 
from django.contrib.auth import views as auth_views

from django.contrib.auth.views import (
    password_change,
    # password_change_done,
)

from .views import (
    # ModelosList,
    not_found_404,
    ingresar,
    salir,
    signup,
    account_activation_sent,
    activate,
    change_password,
    Reiniciar_pass,
    Reiniciar_pass_ConfirmView,
)

app_name = 'usuarios'
urlpatterns = [    
    url(r"^$", ingresar, name='login'),
    url(r"^logout/", salir, name='logout'),
    url(r"^crear/", signup , name='signup'),
    url(r'^password/$', change_password, name='change_password'),
    url(r'^account_activation_sent/$', account_activation_sent, name='account_activation_sent'),
    url(r'^activate/(?P<uidb64>[0-9A-Za-z_\-]+)/(?P<token>[0-9A-Za-z]{1,13}-[0-9A-Za-z]{1,20})/$',
        activate, name='activate'),
    
    
    url(r'^password_reset/$', Reiniciar_pass.as_view(), name='password_reset'),
    url(r'^password_reset/done/$', auth_views.password_reset_done , name='password_reset_done'),
    url(r'^reset/(?P<uidb64>[0-9A-Za-z_\-]+)/(?P<token>[0-9A-Za-z]{1,13}-[0-9A-Za-z]{1,20})/$',
        Reiniciar_pass_ConfirmView.as_view() , name='password_reset_confirm'),
    url(r'^reset/done/$', auth_views.password_reset_complete, name='password_reset_complete'),
]
