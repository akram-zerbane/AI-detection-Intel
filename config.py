import os
from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict

# Dynamically locate the .env file in the agent folder
ENV_FILE_PATH = Path(__file__).resolve().parent / ".env"

class Settings(BaseSettings):
    # Groq LLM Configuration
    GROQ_API_KEY: str
    GROQ_MODEL: str = "openai/gpt-oss-120b"

    # Elasticsearch Configuration (Optional if pushing JSON directly)
    ELASTICSEARCH_URL: str = "http://localhost:9200"
    ELASTIC_USER: str | None = None
    ELASTIC_PASSWORD: str | None = None

    # GitLab Configuration
    GITLAB_URL: str = "https://gitlab.com"
    GITLAB_TOKEN: str = ""
    GITLAB_PROJECT_ID: int = 1

    model_config = SettingsConfigDict(
        env_file=ENV_FILE_PATH,
        env_file_encoding="utf-8",
        extra="ignore"
    )

settings = Settings()
