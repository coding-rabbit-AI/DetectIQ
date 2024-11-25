import os
from pathlib import Path

import environ
from django.core.exceptions import ImproperlyConfigured

from detectiq.globals import DEFAULT_DIRS
from detectiq.core.utils.logging import get_logger

logger = get_logger(__name__)

# Initialize environ with proper typing for paths
env = environ.Env(
    DEBUG=(bool, False),
    OPENAI_API_KEY=(str, ""),
    DJANGO_SECRET_KEY=(str, None),
    RULE_STORAGE_PATH=(str, str(DEFAULT_DIRS.DATA_DIR / "rules")),
    SIGMA_RULE_DIR=(str, str(DEFAULT_DIRS.SIGMA_RULE_DIR)),
    YARA_RULE_DIR=(str, str(DEFAULT_DIRS.YARA_RULE_DIR)),
    SNORT_RULE_DIR=(str, str(DEFAULT_DIRS.SNORT_RULE_DIR)),
    SIGMA_VECTOR_STORE_DIR=(str, str(DEFAULT_DIRS.SIGMA_VECTOR_STORE_DIR)),
    YARA_VECTOR_STORE_DIR=(str, str(DEFAULT_DIRS.YARA_VECTOR_STORE_DIR)),
    SNORT_VECTOR_STORE_DIR=(str, str(DEFAULT_DIRS.SNORT_VECTOR_STORE_DIR)),
)

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent.parent

# Read .env file if it exists
env_file = os.path.join(os.path.dirname(__file__), ".env")
if os.path.exists(env_file):
    env.read_env(env_file)

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = env("DJANGO_SECRET_KEY")
if not SECRET_KEY:
    logger.warning("DJANGO_SECRET_KEY is not set in environment variables")

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = env("DEBUG")

# OpenAI settings - make it optional since we don't always need it
OPENAI_API_KEY = env("OPENAI_API_KEY") or None

ALLOWED_HOSTS = ["localhost", "127.0.0.1"]

# Application definition
INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "rest_framework",
    "corsheaders",
    "detectiq.webapp.backend",
    "detectiq.webapp.backend.api",
    "django_extensions",
]

MIDDLEWARE = [
    "corsheaders.middleware.CorsMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "detectiq.webapp.backend.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "detectiq.webapp.backend.wsgi.application"

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": BASE_DIR / "db.sqlite3",
    }
}

# Password validation
AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.CommonPasswordValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.NumericPasswordValidator",
    },
]

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

STATIC_URL = "static/"
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# CORS settings
CORS_ALLOWED_ORIGINS = [
    "http://localhost:3000",  # Next.js development server
]

CORS_ALLOW_CREDENTIALS = True
CORS_ALLOW_METHODS = [
    "DELETE",
    "GET",
    "OPTIONS",
    "PATCH",
    "POST",
    "PUT",
]

CORS_ALLOW_HEADERS = [
    "accept",
    "accept-encoding",
    "authorization",
    "content-type",
    "dnt",
    "origin",
    "user-agent",
    "x-csrftoken",
    "x-requested-with",
]

# REST Framework settings
REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": [],
    "DEFAULT_PERMISSION_CLASSES": [
        "rest_framework.permissions.AllowAny",
    ],
    "DEFAULT_PAGINATION_CLASS": "rest_framework.pagination.PageNumberPagination",
    "PAGE_SIZE": 10,
    "PAGE_SIZE_QUERY_PARAM": "page_size",
    "MAX_PAGE_SIZE": 100,
}

# Rule directories - use globals.py defaults but allow override from environment
RULE_DIRS = {
    "sigma": Path(env("SIGMA_RULE_DIR")),
    "yara": Path(env("YARA_RULE_DIR")),
    "snort": Path(env("SNORT_RULE_DIR")),
}

# Vector store directories - use globals.py defaults but allow override from environment
VECTOR_STORE_DIRS = {
    "sigma": Path(env("SIGMA_VECTOR_STORE_DIR")),
    "yara": Path(env("YARA_VECTOR_STORE_DIR")),
    "snort": Path(env("SNORT_VECTOR_STORE_DIR")),
}

# Ensure directories exist using os.makedirs instead of Path.mkdir
for directory in [*RULE_DIRS.values(), *VECTOR_STORE_DIRS.values()]:
    os.makedirs(directory, exist_ok=True)

# Add these settings
APPEND_SLASH = True

# Add CORS settings if not already present
CORS_ALLOW_ALL_ORIGINS = True  # For development only
CORS_ALLOW_CREDENTIALS = True
CORS_ALLOWED_ORIGINS = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
]

# Add these settings if not already present
ASGI_APPLICATION = "detectiq.webapp.backend.asgi.application"

# Optional: Configure channels if you're using them
CHANNEL_LAYERS = {"default": {"BACKEND": "channels.layers.InMemoryChannelLayer"}}
