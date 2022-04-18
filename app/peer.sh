pipenv run python manage.py makemigrations
pipenv run python manage.py migrate
pipenv run python manage.py createsuperuser --noinput
pipenv run python manage.py create_identity
pipenv run python manage.py crontab add

echo "$(env ; crontab -l)" | crontab -

service cron start

pipenv run python manage.py runserver  --insecure 0.0.0.0:8000
