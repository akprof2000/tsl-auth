"""tsl-auth-client — клиент TSL Auth (docs/client-contract.md). Без зависимостей; FastAPI/Flask — по желанию."""
from .authz import Denied, Requirement
from .errors import TokenError, TslAuthError
from .options import Options
from .principal import Principal
from .token_client import TokenClient, TokenSet
from .verifier import Verifier, extract_bearer
from .wsgi import TslAuthMiddleware, protect

__all__ = [
    "Denied", "Options", "Principal", "Requirement", "TokenClient", "TokenError", "TokenSet",
    "TslAuthError", "TslAuthMiddleware", "Verifier", "extract_bearer", "protect",
]
