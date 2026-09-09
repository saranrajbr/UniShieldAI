import os
from functools import lru_cache
from typing import Annotated

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "UniShield AI"
    app_version: str = "0.1.0"
    debug: bool = False
    host: str = "0.0.0.0"
    port: int = 8000

    database_url: str = "sqlite+aiosqlite:///./unishield.db"
    db_echo: bool = False

    detection_threshold: float = 0.6
    high_risk_threshold: float = 0.85
    critical_risk_threshold: float = 0.95

    rule_weight_signature: float = 0.30
    rule_weight_statistical: float = 0.25
    rule_weight_behavioral: float = 0.25
    ml_weight_supervised: float = 0.12
    ml_weight_anomaly: float = 0.08

    ml_model_dir: str = "models"
    xgboost_model_path: str = "models/xgboost/model.json"
    isolation_forest_model_path: str = "models/isolation_forest/model.pkl"
    scaler_path: str = "models/preprocessing/scaler.pkl"
    feature_columns_path: str = "models/preprocessing/feature_columns.json"

    pcap_active_path: str = "captures/active/current.pcap"
    pcap_incidents_path: str = "captures/incidents"
    pcap_archive_path: str = "captures/archive"
    pcap_max_bytes: int = 100 * 1024 * 1024
    pcap_rotation_interval_sec: int = 300

    flow_timeout_sec: int = 120
    connection_expiry_sec: int = 300
    rolling_window_sec: int = 60
    dedup_window_sec: int = 300

    max_concurrent_flows: int = 10000
    pipeline_queue_size: int = 50000
    pipeline_consumers: int = 3

    netflow_udp_port: int = 2055
    netflow_udp_host: str = "0.0.0.0"

    zeek_log_path: str = "logs/zeek"
    sensor_endpoint: str = "http://localhost:8000/api/v1/traffic/flow"

    # Annotated with NoDecode so the raw comma-separated env string is passed
    # through to the before-validator instead of being JSON-decoded first.
    cors_origins: Annotated[
        list[str],
        NoDecode,
    ] = ["http://localhost:3000", "http://localhost:5173"]

    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", extra="ignore"
    )

    @field_validator("cors_origins", mode="before")
    @classmethod
    def _parse_cors_list(cls, value):
        if isinstance(value, str):
            return [item.strip() for item in value.split(",") if item.strip()]
        return value


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
