package griffin

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/go-jose/go-jose/v3"
	"github.com/go-resty/resty/v2"
	"github.com/golang-jwt/jwt/v5"
)

type Client struct {
	cfg          *ClientConfig
	http         *resty.Client
	oidcMetadata *OidcServerMetadata
	jwks         map[string]parsedJwk
}

type parsedJwk struct {
	pub *rsa.PublicKey
	kid string
}

type ClientConfig struct {
	ClientID          string
	ClientSecret      string
	Domain            string
	GriffinURL        string
	GriffinBackendURL string // Dev only, not used in production
	OidcRedirectURL   string
}

type OidcServerMetadata struct {
	Issuer                        string   `json:"issuer"`
	AuthorizationEndpoint         string   `json:"authorization_endpoint"`
	TokenEndpoint                 string   `json:"token_endpoint"`
	JwksURI                       string   `json:"jwks_uri"`
	UserInfoEndpoint              string   `json:"userinfo_endpoint"`
	CodeChallengeMethodsSupported []string `json:"code_challenge_methods_supported"`
	GrantTypesSupported           []string `json:"grant_types_supported"`
	ScopesSupported               []string `json:"scopes_supported"`
	ResponseTypesSupported        []string `json:"response_types_supported"`
	AcrValuesSupported            []string `json:"acr_values_supported"`
}

const (
	CodeChallengeMethod         = "S256"
	CodeVerifierNBytes          = 32
	StateNBytes                 = 64
	NonceNBytes                 = 32
	OpenIDConfigurationEndpoint = "/api/v1/openid/.well-known/openid-configuration"
)

func NewClient(cfg *ClientConfig) *Client {
	if !(strings.HasPrefix(cfg.GriffinURL, "http://") || strings.HasPrefix(cfg.GriffinURL, "https://")) {
		panic("GriffinURL must start with http:// or https://")
	}
	if cfg.ClientID == "" {
		panic("ClientID must not be empty")
	}
	if cfg.GriffinBackendURL == "" {
		cfg.GriffinBackendURL = cfg.GriffinURL
	}
	httpClient := resty.New()
	httpClient.SetHostURL(cfg.GriffinBackendURL)
	httpClient.SetHeader("Content-Type", "application/json")
	client := &Client{
		http: httpClient,
		cfg:  cfg,
	}

	return client
}

func (c *Client) Init() error {
	if c.oidcMetadata != nil {
		return nil
	}
	resp, err := c.http.R().Get(OpenIDConfigurationEndpoint)
	if err != nil {
		return err
	}
	if resp.StatusCode() != 200 {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode())
	}
	metadata := &OidcServerMetadata{}
	err = json.Unmarshal(resp.Body(), metadata)
	if err != nil {
		return err
	}
	c.oidcMetadata = metadata

	if err := c.RetrieveJwks(); err != nil {
		return err
	}
	return nil
}

func (c *Client) checkOidcInitialized() error {
	if c.oidcMetadata == nil {
		return fmt.Errorf("Griffin OIDC is not initialized. Perhaps you forgot to call InitOidc()? ")
	}
	return nil
}

// RetrieveJwks retrieves the JSON Web Key Set from the OIDC server and stores
// it in the client. If the client already has a JWK set, it will be replaced.
// If the server rotates its keys, this function must be called again to update
func (c *Client) RetrieveJwks() error {
	resp, err := c.http.R().Get(c.oidcMetadata.JwksURI)
	if err != nil {
		return err
	}
	if resp.StatusCode() != 200 {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode())
	}
	jwks := &jose.JSONWebKeySet{}
	err = json.Unmarshal(resp.Body(), jwks)
	if err != nil {
		return err
	}
	c.jwks = make(map[string]parsedJwk)
	for _, jwk := range jwks.Keys {
		c.jwks[jwk.KeyID] = parsedJwk{
			pub: jwk.Key.(*rsa.PublicKey),
			kid: jwk.KeyID,
		}
	}
	return nil
}

// GenerateLoginRequest generates a login request for the user to authenticate
// with Griffin. This function returns a LoginRequest struct that contains the
// URL to redirect the user to and the verification parameters that must be
// stored in the session, and passed to HandleLoginCallback() to verify the callback.
func (c *Client) GenerateLoginRequest(scopes []string) (*LoginRequest, error) {
	if err := c.checkOidcInitialized(); err != nil {
		return nil, err
	}
	// Use PKCE flow
	codeVerifier, err := generateCodeVerifier()
	codeVerifierStr := base64urlEncode(codeVerifier)
	if err != nil {
		return nil, err
	}
	codeChallengeBytes := generateCodeChallenge(codeVerifier, CodeChallengeMethod)
	codeChallengeStr := base64urlEncode(codeChallengeBytes)
	nonceBytes, err := generateRandomBytes(NonceNBytes)
	if err != nil {
		return nil, err
	}
	nonceStr := base64urlEncode(nonceBytes)
	stateBytes, err := generateRandomBytes(StateNBytes)
	if err != nil {
		return nil, err
	}
	stateStr := base64urlEncode(stateBytes)

	params := url.Values{}
	params.Add("response_type", "code")
	params.Add("response_mode", "query")
	params.Add("client_id", c.cfg.ClientID)
	params.Add("code_challenge_method", CodeChallengeMethod)
	params.Add("code_challenge", codeChallengeStr)
	params.Add("nonce", nonceStr)
	params.Add("state", stateStr)
	params.Add("scope", strings.Join(scopes, " "))
	params.Add("redirect_uri", c.cfg.OidcRedirectURL)
	authURL := fmt.Sprintf("%s?%s", c.oidcMetadata.AuthorizationEndpoint, params.Encode())
	return &LoginRequest{
		AuthURL: authURL,
		AuthVerificationParams: &AuthVerificationParams{
			Nonce:        nonceStr,
			State:        stateStr,
			CodeVerifier: codeVerifierStr,
		},
	}, nil
}

// HandleLoginCallback handles the callback from the OIDC server after the user has authenticated.
// This function verifies the state and nonce, and exchanges the code for ID token and access token.
// The ID token is also verified and the claims are returned in the TokenExchangeResponse.
//
// The verificationParams must be the same as the ones returned by GenerateLoginRequest().
func (c *Client) HandleLoginCallback(cbParams *CallbackParams, verificationParams *AuthVerificationParams) (*TokenExchangeResponse, error) {
	// Verify state
	if cbParams.State != verificationParams.State {
		return nil, fmt.Errorf("state mismatch")
	}
	// Exchange code for token
	tokenResp, err := c.ExchangeToken(cbParams.Code, verificationParams)
	if err != nil {
		return nil, err
	}
	// Verify ID token
	claims, err := c.DecodeIDToken(tokenResp.IDToken)
	if err != nil {
		return nil, err
	}
	// Verify nonce
	if claims.Nonce != verificationParams.Nonce {
		return nil, fmt.Errorf("nonce mismatch")
	}
	tokenResp.IDTokenClaims = claims
	return tokenResp, nil
}

// ExchangeToken exchanges the code for ID token and access token.
//
// The verificationParams must be the same as the ones returned by GenerateLoginRequest().
func (c *Client) ExchangeToken(code string, verificationParams *AuthVerificationParams) (*TokenExchangeResponse, error) {
	if err := c.checkOidcInitialized(); err != nil {
		return nil, err
	}

	body := TokenExchangeRequest{
		ClientID:     c.cfg.ClientID,
		ClientSecret: c.cfg.ClientSecret,
		Code:         code,
		GrantType:    "authorization_code",
		CodeVerifier: verificationParams.CodeVerifier,
	}
	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	res, err := c.http.R().
		SetBody(bodyBytes).
		Post(c.oidcMetadata.TokenEndpoint)

	if err != nil {
		return nil, err
	}
	if res.StatusCode() != 200 {
		return nil, fmt.Errorf("unexpected status code: %d", res.StatusCode())
	}
	resultBytes := res.Body()
	var tokenResp TokenExchangeResponse
	err = json.Unmarshal(resultBytes, &tokenResp)
	return &tokenResp, nil
}

// GetUserinfo gets the user info from the OIDC server using the access token.
func (c *Client) GetUserinfo(accessToken string) (*UserinfoResponse, error) {
	if err := c.checkOidcInitialized(); err != nil {
		return nil, err
	}

	res, err := c.http.R().
		SetAuthToken(accessToken).
		Get(c.oidcMetadata.UserInfoEndpoint)
	if err != nil {
		return nil, err
	}
	bodyBytes := res.Body()
	var userInfoResp UserinfoResponse
	err = json.Unmarshal(bodyBytes, &userInfoResp)
	return &userInfoResp, err
}

// DecodeIDToken decodes the ID token and verifies the signature.
// The claims are returned in the IDTokenClaims struct.
func (c *Client) DecodeIDToken(idTokenString string) (*IDTokenClaims, error) {
	var claims IDTokenClaims
	if err := c.DecodeToken(idTokenString, &claims); err != nil {
		return nil, err
	}
	return &claims, nil
}

// DecodeAccessToken decodes the access token and verifies the signature.
// The claims are returned in the AccessTokenClaims struct.
func (c *Client) DecodeAccessToken(accessTokenString string) (*AccessTokenClaims, error) {
	var claims AccessTokenClaims
	if err := c.DecodeToken(accessTokenString, &claims); err != nil {
		return nil, err
	}
	return &claims, nil
}

// DecodeToken decodes the token and verifies the signature.
// The token is verified using the keys from the JWKS endpoint.
// If the key is not found in the JWKS, the JWKS is refreshed and the key is looked up again.
// This simple retry mechanism is used to catch up with key rotation.
func (c *Client) DecodeToken(tokenString string, claims jwt.Claims) error {
	retried := false
	shouldRetry := false
TO_RETRY:
	_, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("kid not found in token header")
		}
		alg, ok := token.Header["alg"].(string)
		if !ok {
			return nil, fmt.Errorf("alg not found in token header")
		}
		if alg != "RS256" {
			return nil, fmt.Errorf("unexpected algorithm: %s", alg)
		}
		// If the kid is not found in the JWKS, retrieve the JWKS again once
		if jwk, ok := c.jwks[kid]; ok {
			return jwk.pub, nil
		} else {
			if !retried {
				c.RetrieveJwks()
				shouldRetry = true
			}
			return nil, fmt.Errorf("kid not found in the keyset: %s", kid)
		}
	}, jwt.WithAudience(c.cfg.ClientID), jwt.WithIssuer(c.oidcMetadata.Issuer))
	if err != nil {
		// If we haven't retried yet, retry once after retrieving the JWKS
		if shouldRetry && !retried {
			retried = true
			shouldRetry = false
			goto TO_RETRY
		}
		return err
	}
	return nil
}

// MakeCookieForAuthVerificationParams creates a cookie with the given name and value from the AuthVerificationParams.
// The cookie is used to verify the state and nonce in the callback.
// In order to get the AuthVerificationParams from the cookie, use GetAuthVerificationParamsFromCookie().
func MakeCookieForAuthVerificationParams(cookieName string, params *AuthVerificationParams) *http.Cookie {
	jsonBytes := mustMarshalJSON(params)
	cookieValue := base64.RawURLEncoding.EncodeToString(jsonBytes)
	return &http.Cookie{
		Name:     cookieName,
		Path:     "/",
		Value:    cookieValue,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	}
}

// GetAuthVerificationParamsFromCookie get the AuthVerificationParams from the cookie.
// The cookie must have been created by MakeCookieForAuthVerificationParams().
func GetAuthVerificationParamsFromCookie(cookie *http.Cookie) (*AuthVerificationParams, error) {
	jsonBytes, err := base64.RawURLEncoding.DecodeString(cookie.Value)
	if err != nil {
		return nil, err
	}
	var params AuthVerificationParams
	if err := json.Unmarshal(jsonBytes, &params); err != nil {
		return nil, err
	}
	return &params, err
}
