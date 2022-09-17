from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static


urlpatterns = [
    path("admin/", admin.site.urls),
    path('dj-rest-auth/', include('dj_rest_auth.urls')),
    path('dj-rest-auth/registration/', include('dj_rest_auth.registration.urls')),
    path("", include("checkout.urls")),
    path("", include("accounts.urls")),
    path("", include("inventory.urls")),
    path("", include("main.urls")),
    path("search/", include("search.urls")),
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
