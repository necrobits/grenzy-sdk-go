package grenzy

import "github.com/golang-jwt/jwt/v5"

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
	UserID   string   `json:"uid,omitempty"`
	Nonce    string   `json:"nonce,omitempty"`
	AuthTime int64    `json:"auth_time,omitempty"`
	AMR      []string `json:"amr,omitempty"`
	ACR      string   `json:"acr,omitempty"`
}

type AccessTokenClaims struct {
	jwt.RegisteredClaims
	UserID    string `json:"uid,omitempty"`
	ClientID  string `json:"cid,omitempty"`
	SessionID string `json:"sid,omitempty"`
	Scopes    string `json:"scopes,omitempty"`
	AuthTime  int64  `json:"auth_time,omitempty"`
	ACR       string `json:"acr,omitempty"`
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
	AccessToken   string         `json:"access_token,omitempty"`
	IDToken       string         `json:"id_token,omitempty"`
	RefreshToken  string         `json:"refresh_token,omitempty"`
	IDTokenClaims *IDTokenClaims `json:"id_token_claims,omitempty"`
}

type UserinfoResponse struct {
	Username            string                 `json:"username,omitempty"`
	Email               string                 `json:"email,omitempty"`
	EmailVerified       bool                   `json:"email_verified,omitempty"`
	PhoneNumber         string                 `json:"phone_number,omitempty"`
	PhoneNumberVerified bool                   `json:"phone_number_verified,omitempty"`
	Profile             map[string]interface{} `json:"profile,omitempty"`
}
