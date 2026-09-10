from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "Dataset Security Gateway"
    environment: str = "development"

    database_url: str = "postgresql+asyncpg://postgres:postgres@localhost:5432/dataset_security"
    redis_url: str = "redis://localhost:6379/0"
    opa_url: str = "http://localhost:8181/v1/data/dataset_policy"

    # LLM settings
    gemini_api_key: str | None = None
    groq_api_key: str | None = None
    gemini_model: str = "gemini/gemini-2.5-flash"
    groq_model: str = "groq/llama-3.3-70b-versatile"

    # Storage
    object_storage_endpoint: str | None = None
    object_storage_bucket: str = "datasets"
    object_storage_region: str = "ap-south-1"

    # Browser origins
    cors_origins: str = "http://localhost:3000,http://127.0.0.1:3000"

    model_config = SettingsConfigDict(
        env_file=".env",
        extra="ignore",
    )

    @property
    def cors_origin_list(self) -> list[str]:
        return [x.strip() for x in self.cors_origins.split(",") if x.strip()]


settings = Settings()
