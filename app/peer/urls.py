from django.urls import path

from . import views

urlpatterns = [
    path('join-auction', views.join_auction, name='join_auction'),
    path('bid', views.bid, name='bid_auction'),
]
