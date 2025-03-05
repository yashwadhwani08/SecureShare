from rest_framework import viewsets, permissions
from rest_framework.response import Response
from .models import File
from .serializers import FileSerializer

class FileViewSet(viewsets.ModelViewSet):
    queryset = File.objects.all()
    serializer_class = FileSerializer

    def get_permissions(self):
        if self.action in ['create', 'destroy']:
            self.permission_classes = [permissions.IsAuthenticated]
        elif self.action == 'list':
            self.permission_classes = [permissions.AllowAny]
        return super().get_permissions()

    def perform_create(self, serializer):
        serializer.save(owner=self.request.user)