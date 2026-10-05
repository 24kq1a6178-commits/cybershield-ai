from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', include('core.urls')),            # home, about, help, search
    path('scan/', include('scanner.urls')),    # scanner endpoints
]