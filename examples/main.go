package main

import (
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/necrobits/grenzy-sdk-go/grenzy"
	"github.com/necrobits/grenzy-sdk-go/grenzysp"
)

func main() {
	clientCfg := &grenzy.ClientConfig{
		ClientID:         "clientid",
		ClientSecret:     "clientsecret",
		Domain:           "localhost:1234",
		GrenzyURL:        "http://localhost:4000",
		GrenzyBackendURL: "http://localhost:8080",
		OidcRedirectURL:  "http://localhost:1234/callback",
	}
	grenzyClient := grenzy.NewClient(clientCfg)
	err := grenzyClient.Init()
	if err != nil {
		panic(err)
	}
	echoSp := grenzysp.NewEchoSupport(grenzyClient)

	e := echo.New()

	e.GET("/", func(c echo.Context) error {
		return c.String(http.StatusOK, "Hello, World!")
	})

	e.GET("/login", echoSp.BuildLoginRequestHandler([]string{"openid", "profile", "email"}))

	e.GET("/callback", echoSp.BuildCallbackHandler(func(c echo.Context, tokenResponse *grenzy.TokenExchangeResponse) error {
		accessTokenClaims, err := echoSp.Client.DecodeAccessToken(tokenResponse.AccessToken)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
		}
		userinfo, err := grenzyClient.GetUserinfo(tokenResponse.AccessToken)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, err)
		}
		resp := map[string]interface{}{
			"tokenResponse":       tokenResponse,
			"userinfo":            userinfo,
			"access_token_claims": accessTokenClaims,
		}
		return c.JSON(http.StatusOK, resp)
	}))

	e.Logger.Fatal(e.Start(":1234"))
}
