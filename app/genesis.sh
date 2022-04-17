pipenv run python manage.py makemigrations
pipenv run python manage.py migrate
pipenv run python manage.py create_admin_user
pipenv run python manage.py create_identity
pipenv run python manage.py create_genesis_block
pipenv run python manage.py runserver 0.0.0.0:8000
