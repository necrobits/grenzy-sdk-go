package griffin

import "github.com/golang-jwt/jwt/v5"

type TokenResponse struct {
	AccessToken   string `json:"access_token,omitempty"`
	IDToken       string `json:"id_token,omitempty"`
	IDTokenClaims *IDTokenClaims
}

type AuthVerificationParams struct {
	Nonce        string `json:"nonce,omitempty"`
	State        string `json:"state,omitempty"`
	CodeVerifier string `json:"code_verifier,omitempty"`
}

type CallbackParams struct {
	Code  string
	State string
}

type LoginRequest struct {
	AuthVerificationParams *AuthVerificationParams
	AuthURL                string
}

type IDTokenClaims struct {
	jwt.RegisteredClaims
	Nonce    string   `json:"nonce,omitempty"`
	AuthTime int64    `json:"auth_time,omitempty"`
	AMR      []string `json:"amr,omitempty"`
	ACR      string   `json:"acr,omitempty"`
}

type TokenExchangeRequest struct {
	Code         string `json:"code,omitempty"`
	ClientID     string `json:"client_id,omitempty"`
	ClientSecret string `json:"client_secret,omitempty"`
	GrantType    string `json:"grant_type,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	CodeVerifier string `json:"code_verifier,omitempty"`
}

type TokenExchangeResponse struct {
	AccessToken  string `json:"access_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

type UserInfoResponse struct {
	Username            string                 `json:"username,omitempty"`
	Email               string                 `json:"email,omitempty"`
	EmailVerified       bool                   `json:"email_verified,omitempty"`
	PhoneNumber         string                 `json:"phone_number,omitempty"`
	PhoneNumberVerified bool                   `json:"phone_number_verified,omitempty"`
	Profile             map[string]interface{} `json:"profile,omitempty"`
}

type JWKSResponse struct {
	Keys []JWKResponse `json:"keys,omitempty"`
}

type JWKResponse struct {
	Kty string `json:"kty,omitempty"`
	Alg string `json:"alg,omitempty"`
	Use string `json:"use,omitempty"`
	Kid string `json:"kid,omitempty"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
}
