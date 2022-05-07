from django.urls import path

from . import views

urlpatterns = [
    path('ping', views.ping, name='ping_genesis'),
    path('create-genesis-block', views.create_genesis_block, name="create_genesis_block"),
    path('auctions/start', views.start_auction, name='start_auction'),
    path('auctions/<str:auction_id>/change-state', views.change_auction_state, name="change_auction_state")
]
