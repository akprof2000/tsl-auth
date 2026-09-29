package tslauth

import "errors"

// Коды ошибок проверки токена (контракт §2). Код — часть контракта, текст описания — нет.
const (
	CodeMissing                  = "missing"
	CodeMalformed                = "malformed"
	CodeUnsupportedAlg           = "unsupported_alg"
	CodeUnknownKey               = "unknown_key"
	CodeBadSignature             = "bad_signature"
	CodeBadIssuer                = "bad_issuer"
	CodeExpired                  = "expired"
	CodeNotYetValid              = "not_yet_valid"
	CodeBadAudience              = "bad_audience"
	CodeRevoked                  = "revoked"
	CodeIntrospectionUnavailable = "introspection_unavailable"
)

// AuthError — ошибка проверки токена. Code — строка из §2, Err — причина (например, сетевая ошибка
// introspection); ничего из содержимого токена в ошибку не попадает.
type AuthError struct {
	Code string
	Err  error
}

func (e *AuthError) Error() string {
	if e.Err != nil {
		return "tslauth: " + e.Code + ": " + e.Err.Error()
	}
	return "tslauth: " + e.Code
}

// Unwrap отдаёт причину для errors.Is/errors.As.
func (e *AuthError) Unwrap() error { return e.Err }

// Is делает errors.Is(err, ErrExpired) истинным для любой AuthError с тем же кодом.
func (e *AuthError) Is(target error) bool {
	t, ok := target.(*AuthError)
	return ok && t.Code == e.Code
}

// Sentinel-ошибки для errors.Is: errors.Is(err, tslauth.ErrExpired).
var (
	ErrMissing                  = &AuthError{Code: CodeMissing}
	ErrMalformed                = &AuthError{Code: CodeMalformed}
	ErrUnsupportedAlg           = &AuthError{Code: CodeUnsupportedAlg}
	ErrUnknownKey               = &AuthError{Code: CodeUnknownKey}
	ErrBadSignature             = &AuthError{Code: CodeBadSignature}
	ErrBadIssuer                = &AuthError{Code: CodeBadIssuer}
	ErrExpired                  = &AuthError{Code: CodeExpired}
	ErrNotYetValid              = &AuthError{Code: CodeNotYetValid}
	ErrBadAudience              = &AuthError{Code: CodeBadAudience}
	ErrRevoked                  = &AuthError{Code: CodeRevoked}
	ErrIntrospectionUnavailable = &AuthError{Code: CodeIntrospectionUnavailable}
)

// ErrorCode возвращает код §2 из ошибки Verify (или "" для чужой ошибки).
func ErrorCode(err error) string {
	var ae *AuthError
	if errors.As(err, &ae) {
		return ae.Code
	}
	return ""
}

func authErr(code string, cause error) *AuthError { return &AuthError{Code: code, Err: cause} }
