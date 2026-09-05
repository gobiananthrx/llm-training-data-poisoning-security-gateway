from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "Dataset Security Gateway"
    environment: str = "development"

    database_url: str

    # Object storage is S3-compatible in deployment.
    # MinIO can be used locally without changing the application contract.
    object_storage_endpoint: str | None = None
    object_storage_bucket: str = "datasets"
    object_storage_region: str = "ap-south-1"

    # Comma-separated browser origins.
    cors_origins: str = "http://localhost:3000"

    model_config = SettingsConfigDict(
        env_file=".env",
        extra="ignore",
    )

    @property
    def cors_origin_list(self) -> list[str]:
        return [x.strip() for x in self.cors_origins.split(",") if x.strip()]


settings = Settings()
