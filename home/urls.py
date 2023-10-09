from django.urls import path

from . import views

urlpatterns = [
    path("", views.index, name="index"),
    path("starter/", views.starter, name="starter"),
    path("new-target/", views.new_target, name="new_target"),
    path("new-scan/", views.new_scan, name="new_scan"),
    path("scans/<int:scan_id>/", views.scan_details, name="scan_details"),
    path("targets/<int:target_id>/", views.target_details, name="target_details"),
    path('delete_scans/', views.delete_scans, name='delete_scans'),
]
