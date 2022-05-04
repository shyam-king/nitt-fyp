from django.urls import path

from . import views

urlpatterns = [
    path('ping', views.ping, name='ping_genesis'),
    path('auctions/start', views.start_auction, name='start_auction'),
    path('auctions/<str:auction_id>', views.get_auction_state, name='get_auction'),
]
