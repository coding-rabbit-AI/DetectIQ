.SILENT: install/backend/dependencies install/frontend/dependencies install/backend start/backend start/frontend run/local

APP_NAME ?= ""

install/backend/dependencies:
	@echo "\033[1;33m[*] Installing '$(APP_NAME)' backend dependencies\033[0m"
	poetry install --all-extras

install/backend: install/backend/dependencies
	@echo "\033[1;33m[*] Building '$(APP_NAME)' backend\033[0m"
	cd detectiq/ &&\
	poetry run python manage.py migrate &&\
	poetry run python manage.py initialize_rulesets --create_vectorstores &&\
	poetry run python manage.py initialize_rulesets --rule_types sigma yara &&\
	poetry run python manage.py initialize_rulesets --rule_types snort --force 

install/frontend/dependencies:
	@echo "\033[1;33m[*] Installing '$(APP_NAME)' frontend dependencies\033[0m"
	cd detectiq/webapp/frontend &&\
	npm install

install/local: install/backend install/frontend/dependencies
	@echo "\033[1;32m[!] Installing '${APP_NAME}'\033[0m"

start/backend:
	@echo "\033[1;33m[*] Starting '$(APP_NAME)' backend\033[0m"
	cd detectiq/webapp/backend &&\
	poetry run python manage.py runserver &
	sleep 10

start/frontend: 
	@echo "\033[1;33m[*] Starting '$(APP_NAME)' frontend\033[0m"
	cd detectiq/webapp/frontend &&\
	npm run dev

run/local: start/backend start/frontend
	@echo "\033[1;33m[*] Running '$(APP_NAME)'\033[0m"
