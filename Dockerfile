FROM python:3.13.1
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
CMD sh -c "python manage.py migrate && \
           python manage.py shell -c \"
from django.contrib.auth import get_user_model
User = get_user_model()
if not User.objects.filter(username='svd_admin').exists():
    User.objects.create_superuser('svd_admin', 'noreply.serviceday@gmail.com', 'Svd1234*')
    print('Superuser created.')
else:
    print('Superuser already exists.')
\" && \
           python manage.py migrate && \
           python manage.py runserver 0.0.0.0:\${PORT:-8000}"