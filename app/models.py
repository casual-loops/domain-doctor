from typing import Literal

from pydantic import BaseModel


class CheckResult(BaseModel):
    name: str
    category: str
    status: Literal["pass", "warn", "fail"]
    summary: str
    detail: str | None = None
