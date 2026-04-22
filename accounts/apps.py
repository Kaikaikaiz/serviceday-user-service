from django.apps import AppConfig


class AccountsConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'accounts'

    def ready(self):
        from django.db.models.signals import post_migrate
        post_migrate.connect(_setup_groups_and_users, sender=self)


def _setup_groups_and_users(sender, **kwargs):
    # auto-creates Employee + Administrator groups after migrations
    try:
        from django.contrib.auth.models import User, Group

        employee_group, _ = Group.objects.get_or_create(name="Employee")
        admin_group, _    = Group.objects.get_or_create(name="Administrator")

        for user in User.objects.filter(is_staff=True):
            if not user.groups.filter(name="Administrator").exists():
                user.groups.add(admin_group)

        for user in User.objects.filter(is_staff=False):
            if not user.groups.exists():
                user.groups.add(employee_group)

    except Exception:
        pass