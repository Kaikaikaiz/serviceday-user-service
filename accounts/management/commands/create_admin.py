from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model

class Command(BaseCommand):
    def handle(self, *args, **kwargs):
        User = get_user_model()

        if not User.objects.filter(username='svd_admin').exists():
            User.objects.create_superuser(
                username='svd_admin',
                email='noreply.serviceday@gmail.com',
                password='Svd1234*'
            )
            self.stdout.write(self.style.SUCCESS("Admin created"))
        else:
            self.stdout.write("Admin already exists")