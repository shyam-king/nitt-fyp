from django.urls import path

from . import views

urlpatterns = [
    path('query', views.query_blocks, name='query_blocks'),
    path('<str:block_id>', views.view_block, name='view_block'),
    path('', views.push_block, name='push_block'),
]
