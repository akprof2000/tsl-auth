"""Исключения SDK. Коды ошибок проверки — из docs/client-contract.md §2."""
from __future__ import annotations


class TslAuthError(Exception):
    """Проверка access-токена не пройдена. `code` — часть контракта, `description` — нет."""

    def __init__(self, code: str, description: str | None = None):
        super().__init__(description or code)
        self.code = code
        self.description = description or code

    def __str__(self) -> str:
        return self.code if self.description == self.code else f"{self.code}: {self.description}"


class TokenError(Exception):
    """Ошибка клиента токенов (§6): 4xx с JSON `error`, либо `unavailable` для сети/5xx."""

    def __init__(self, error: str, error_description: str | None = None, status: int = 0):
        super().__init__(f"{error}: {error_description}" if error_description else error)
        self.error = error
        self.error_description = error_description
        self.status = status
