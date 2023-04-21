package griffin

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/go-resty/resty/v2"
)

type Client struct {
	cfg  *ClientConfig
	http *resty.Client
}

type ClientConfig struct {
	ClientID          string
	ClientSecret      string
	Domain            string
	GriffinURL        string
	GriffinBackendURL string // Dev only, not used in production
	RedirectURL       string
}

const (
	CodeChallengeMethod = "S256"
	CodeVerifierNBytes  = 32
	StateNBytes         = 64
	NonceNBytes         = 32
	TokenEndpoint       = "/api/v1/openid/token"
	UserInfoEndpoint    = "/api/v1/openid/userinfo"
	AuthorizeEndpoint   = "/openid/authorize"
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
	return &Client{
		http: httpClient,
		cfg:  cfg,
	}
}

// GenerateLoginRequest generates a login request for the user to authenticate
// with Griffin. This function returns a LoginRequest struct that contains the
// URL to redirect the user to and the verification parameters that must be
// stored in the session, and passed to HandleLoginRedirectCallback() to verify the callback.
func (c *Client) GenerateLoginRequest(scopes []string) (*LoginRequest, error) {
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
	authURL := fmt.Sprintf("%s%s?%s", c.cfg.GriffinURL, AuthorizeEndpoint, params.Encode())
	return &LoginRequest{
		AuthURL: authURL,
		AuthVerificationParams: &AuthVerificationParams{
			Nonce:        nonceStr,
			State:        stateStr,
			CodeVerifier: codeVerifierStr,
		},
	}, nil
}

func (c *Client) HandleLoginRedirectCallback(cbParams *CallbackParams, verificationParams *AuthVerificationParams) (*TokenResponse, error) {
	// Verify state
	if cbParams.State != verificationParams.State {
		return nil, fmt.Errorf("state mismatch")
	}
	// Verify nonce

	// Exchange code for token
	tokenResp, err := c.ExchangeToken(cbParams.Code, verificationParams)
	if err != nil {
		return nil, err
	}
	return tokenResp, nil
}

func (c *Client) ExchangeToken(code string, verificationParams *AuthVerificationParams) (*TokenResponse, error) {
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
		Post(TokenEndpoint)

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

func (c *Client) GetUserInfo(accessToken string) (*UserInfoResponse, error) {
	res, err := c.http.R().
		SetAuthToken(accessToken).
		Get(UserInfoEndpoint)
	if err != nil {
		return nil, err
	}
	bodyBytes := res.Body()
	var userInfoResp UserInfoResponse
	err = json.Unmarshal(bodyBytes, &userInfoResp)
	return &userInfoResp, err
}

func (c *Client) DecodeIDToken(idToken string) (*IDTokenData, error) {
	return nil, nil
}

func generateCodeVerifier() ([]byte, error) {
	return generateRandomBytes(CodeVerifierNBytes)
}

func generateCodeChallenge(codeVerifier []byte, method string) []byte {
	return mustHashUsing(method, codeVerifier)
}
