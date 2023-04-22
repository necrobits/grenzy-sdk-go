package griffin

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/go-jose/go-jose/v3"
	"github.com/go-resty/resty/v2"
	"github.com/golang-jwt/jwt/v5"
)

type OidcClient struct {
	cfg      *OidcClientConfig
	http     *resty.Client
	metadata *OidcServerMetadata
	jwks     map[string]JWK
}

type JWK struct {
	pub *rsa.PublicKey
	kid string
}

type OidcClientConfig struct {
	ClientID          string
	ClientSecret      string
	Domain            string
	GriffinURL        string
	GriffinBackendURL string // Dev only, not used in production
	RedirectURL       string
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

func NewOidcClient(cfg *OidcClientConfig) *OidcClient {
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
	client := &OidcClient{
		http: httpClient,
		cfg:  cfg,
	}

	return client
}

func (c *OidcClient) Init() error {
	if c.metadata != nil {
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
	c.metadata = metadata
	fmt.Printf("%+v\n", c.metadata)

	if err := c.RetrieveJwks(); err != nil {
		return err
	}
	return nil
}

// RetrieveJwks retrieves the JSON Web Key Set from the OIDC server and stores
// it in the client. If the client already has a JWK set, it will be replaced.
// If the server rotates its keys, this function must be called again to update (somehow, maybe when the kid doesn't match)
func (c *OidcClient) RetrieveJwks() error {
	resp, err := c.http.R().Get(c.metadata.JwksURI)
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
	c.jwks = make(map[string]JWK)
	for _, jwk := range jwks.Keys {
		c.jwks[jwk.KeyID] = JWK{
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
func (c *OidcClient) GenerateLoginRequest(scopes []string) (*LoginRequest, error) {
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
	params.Add("redirect_uri", c.cfg.RedirectURL)
	authURL := fmt.Sprintf("%s?%s", c.metadata.AuthorizationEndpoint, params.Encode())
	return &LoginRequest{
		AuthURL: authURL,
		AuthVerificationParams: &AuthVerificationParams{
			Nonce:        nonceStr,
			State:        stateStr,
			CodeVerifier: codeVerifierStr,
		},
	}, nil
}

func (c *OidcClient) HandleLoginCallback(cbParams *CallbackParams, verificationParams *AuthVerificationParams) (*TokenResponse, error) {
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

func (c *OidcClient) ExchangeToken(code string, verificationParams *AuthVerificationParams) (*TokenResponse, error) {
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
		Post(c.metadata.TokenEndpoint)

	if err != nil {
		return nil, err
	}
	if res.StatusCode() != 200 {
		return nil, fmt.Errorf("unexpected status code: %d", res.StatusCode())
	}
	resultBytes := res.Body()
	var tokenResp TokenResponse
	err = json.Unmarshal(resultBytes, &tokenResp)
	return &tokenResp, nil
}

func (c *OidcClient) GetUserInfo(accessToken string) (*UserInfoResponse, error) {
	res, err := c.http.R().
		SetAuthToken(accessToken).
		Get(c.metadata.UserInfoEndpoint)
	if err != nil {
		return nil, err
	}
	bodyBytes := res.Body()
	var userInfoResp UserInfoResponse
	err = json.Unmarshal(bodyBytes, &userInfoResp)
	return &userInfoResp, err
}

func (c *OidcClient) DecodeIDToken(idTokenString string) (*IDTokenClaims, error) {
	var claims IDTokenClaims
	_, err := jwt.ParseWithClaims(idTokenString, &claims, func(token *jwt.Token) (interface{}, error) {
		fmt.Printf("token: %+v", token.Header)
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
		if jwk, ok := c.jwks[kid]; ok {
			return jwk.pub, nil
		} else {
			return nil, fmt.Errorf("kid not found in the keyset: %s", kid)
		}
	}, jwt.WithAudience(c.cfg.ClientID), jwt.WithIssuer(c.metadata.Issuer))
	if err != nil {
		return nil, err
	}
	return &claims, nil
}

func generateCodeVerifier() ([]byte, error) {
	return generateRandomBytes(CodeVerifierNBytes)
}

func generateCodeChallenge(codeVerifier []byte, method string) []byte {
	return mustHashUsing(method, codeVerifier)
}
