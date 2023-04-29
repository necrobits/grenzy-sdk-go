package grenzy_test

import (
	"os"
	"strings"
	"testing"

	"github.com/necrobits/grenzy-sdk-go/grenzy"
)

var grenzyClient *grenzy.Client
var clientCfg *grenzy.ClientConfig

func setup() {
	// setup code
	clientCfg = &grenzy.ClientConfig{
		ClientID:        "r9eo4WLGPr8O",
		ClientSecret:    "ulxwDX7fSCnN0p8D",
		Domain:          "localhost:1234",
		GrenzyURL:       "http://localhost:4000",
		OidcRedirectURL: "http://localhost:1234/callback",
	}
	grenzyClient = grenzy.NewClient(clientCfg)
}

func shutdown() {
	// shutdown code
}

func TestMain(m *testing.M) {
	setup()
	code := m.Run()
	shutdown()
	os.Exit(code)
}

func TestGenerateLoginURL(t *testing.T) {
	loginRequest, err := grenzyClient.GenerateLoginRequest([]string{"openid", "profile", "email"})
	if err != nil {
		t.Error(err)
	}
	if !strings.HasPrefix(loginRequest.AuthURL, clientCfg.GrenzyURL) {
		t.Error("AuthURL must start with GrenzyURL")
	}
	t.Log("AuthURL:", loginRequest.AuthURL)
}
