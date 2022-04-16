from django.urls import path

from . import views

urlpatterns = [
    path('<str:block_id>', views.view_block, name='view_block'),
]
