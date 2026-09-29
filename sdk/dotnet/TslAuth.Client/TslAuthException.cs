namespace TslAuth.Client;

/// <summary>Коды ошибок проверки токена (docs/client-contract.md §2). Код — часть контракта, описание — нет.</summary>
public static class TslAuthErrorCodes
{
    /// <summary>Токен не передан.</summary>
    public const string Missing = "missing";
    /// <summary>Не JWT: не три части, не base64url/JSON, нет <c>kid</c>.</summary>
    public const string Malformed = "malformed";
    /// <summary><c>alg</c> не RS256.</summary>
    public const string UnsupportedAlg = "unsupported_alg";
    /// <summary>Ключ <c>kid</c> не найден в JWKS.</summary>
    public const string UnknownKey = "unknown_key";
    /// <summary>Подпись неверна.</summary>
    public const string BadSignature = "bad_signature";
    /// <summary><c>iss</c> не совпадает с настроенным issuer.</summary>
    public const string BadIssuer = "bad_issuer";
    /// <summary>Срок действия истёк.</summary>
    public const string Expired = "expired";
    /// <summary><c>nbf</c> ещё не наступил.</summary>
    public const string NotYetValid = "not_yet_valid";
    /// <summary><c>aud</c> не содержит audience этого API.</summary>
    public const string BadAudience = "bad_audience";
    /// <summary>Интроспекция вернула <c>active: false</c>.</summary>
    public const string Revoked = "revoked";
    /// <summary>Introspection endpoint недоступен.</summary>
    public const string IntrospectionUnavailable = "introspection_unavailable";
}

/// <summary>Ошибка проверки access-токена: <see cref="Code"/> — строка из §2 контракта.</summary>
public sealed class TslAuthException : Exception
{
    /// <summary>Создаёт ошибку с кодом контракта и человекочитаемым описанием.</summary>
    public TslAuthException(string code, string message, Exception? inner = null) : base(message, inner) => Code = code;

    /// <summary>Код ошибки (<see cref="TslAuthErrorCodes"/>).</summary>
    public string Code { get; }
}
