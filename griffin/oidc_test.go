package griffin_test

import (
	"os"
	"strings"
	"testing"

	"github.com/necrobits/griffin-sdk-go/griffin"
)

var griffinClient *griffin.OidcClient
var clientCfg *griffin.OidcClientConfig

func setup() {
	// setup code
	clientCfg = &griffin.OidcClientConfig{
		ClientID:     "r9eo4WLGPr8O",
		ClientSecret: "ulxwDX7fSCnN0p8D",
		Domain:       "localhost:1234",
		GriffinURL:   "http://localhost:4000",
		RedirectURL:  "http://localhost:1234/callback",
	}
	griffinClient = griffin.NewOidcClient(clientCfg)
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
	loginRequest, err := griffinClient.GenerateLoginRequest([]string{"openid", "profile", "email"})
	if err != nil {
		t.Error(err)
	}
	if !strings.HasPrefix(loginRequest.AuthURL, clientCfg.GriffinURL) {
		t.Error("AuthURL must start with GriffinURL")
	}
	t.Log("AuthURL:", loginRequest.AuthURL)
}
