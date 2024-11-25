from setuptools import find_packages, setup

setup(
    name="detectiq",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "django>=4.2.0",
        "djangorestframework>=3.14.0",
        "django-cors-headers>=4.3.0",
        "langchain>=0.0.350",
        "langchain-openai>=0.0.2",
        "langchain-core>=0.1.0",
        "langchain-community>=0.0.10",
        "python-dotenv>=1.0.0",
        "django-environ>=0.11.2",
        "openai>=1.0.0",
        "aiohttp>=3.8.0",
        "faiss-cpu>=1.7.4",
        "pydantic>=2.0.0",
        "pydantic-settings>=2.0.0",
    ],
    python_requires=">=3.9",
)
