"""
Pydantic schemas — Request models.
"""

from pydantic import BaseModel, HttpUrl, Field, field_validator
from typing import Optional


class AnalyzeRequest(BaseModel):
    url: str = Field(
        ...,
        min_length=4,
        max_length=2048,
        description="The URL to analyze (shortened, normal, or suspicious).",
        examples=["https://bit.ly/example", "http://192.168.1.1/phish"],
    )
    follow_redirects: bool = Field(
        default=True,
        description="Whether to follow and record the full redirect chain.",
    )
    timeout: Optional[int] = Field(
        default=None,
        ge=1,
        le=30,
        description="Per-hop timeout in seconds. Defaults to server setting.",
    )

    @field_validator("url")
    @classmethod
    def url_must_have_scheme(cls, v: str) -> str:
        v = v.strip()
        if not v.startswith(("http://", "https://", "ftp://")):
            v = "http://" + v
        return v
