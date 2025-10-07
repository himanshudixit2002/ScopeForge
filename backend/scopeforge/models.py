from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, StrictBool, field_validator

Profile = Literal["headers", "web"]


class RequestModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ProgramCreate(RequestModel):
    name: str = Field(min_length=2, max_length=120)
    policy_url: str = Field(min_length=8, max_length=2048)
    authorization_note: str = Field(min_length=12, max_length=4000)
    scope_origins: list[str] = Field(min_length=1, max_length=100)
    excluded_paths: list[str] = Field(default_factory=list, max_length=100)
    request_interval_ms: int = Field(default=1500, ge=1000, le=60000, strict=True)
    authorization_expires_at: str = Field(max_length=64)
    authorized: StrictBool
    allowed_profiles: list[Profile] = Field(default_factory=lambda: ["headers"], min_length=1, max_length=2)

    @field_validator("allowed_profiles")
    @classmethod
    def unique_profiles(cls, value):
        if len(set(value)) != len(value):
            raise ValueError("Choose each allowed profile only once.")
        return value


class ScanCreate(RequestModel):
    program_id: str = Field(min_length=1, max_length=64)
    target_url: str = Field(min_length=8, max_length=2048)
    mode: Literal["demo", "passive"]
    profile: Profile = "headers"


class ScanBatchCreate(RequestModel):
    program_id: str = Field(min_length=1, max_length=64)
    target_urls: list[str] = Field(min_length=1, max_length=20)
    profile: Profile = "headers"


class ScanCancelAll(RequestModel):
    program_id: str | None = Field(default=None, min_length=1, max_length=64)


class ImportCreate(RequestModel):
    program_id: str = Field(min_length=1, max_length=64)
    target_url: str = Field(min_length=8, max_length=2048)
    format: Literal["http", "openapi"]
    content: str = Field(min_length=2, max_length=256 * 1024)

    @field_validator("content")
    @classmethod
    def bounded_utf8(cls, value):
        if len(value.encode("utf-8")) > 256 * 1024:
            raise ValueError("Import content is limited to 256 KiB of UTF-8.")
        return value


class FindingCreate(RequestModel):
    program_id: str = Field(min_length=1, max_length=64)
    target_url: str = Field(min_length=8, max_length=2048)
    title: str = Field(min_length=3, max_length=200)
    severity: Literal["high", "medium", "low", "info"]
    confidence: Literal["high", "medium", "low"]
    description: str = Field(min_length=10, max_length=4000)
    impact: str = Field(min_length=10, max_length=4000)
    remediation: str = Field(min_length=10, max_length=4000)
    evidence: str = Field(min_length=3, max_length=8000)
    cwe: str | None = Field(default=None, pattern=r"^CWE-[1-9][0-9]{0,5}$")
    notes: str = Field(default="", max_length=4000)

    @field_validator("title", "description", "impact", "remediation", "evidence")
    @classmethod
    def meaningful_text(cls, value):
        if not value.strip():
            raise ValueError("Provide meaningful, sanitized analyst text.")
        return value.strip()


class FindingUpdate(RequestModel):
    status: Literal["open", "validated", "dismissed", "reported"]
    notes: str | None = Field(default=None, max_length=10000)
