package main

import (
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/necrobits/griffin-sdk-go/griffin"
	"github.com/necrobits/griffin-sdk-go/griffinsp"
)

func main() {
	clientCfg := &griffin.ClientConfig{
		ClientID:          "clientid",
		ClientSecret:      "clientsecret",
		Domain:            "localhost:1234",
		GriffinURL:        "http://localhost:4000",
		GriffinBackendURL: "http://localhost:8080",
		OidcRedirectURL:   "http://localhost:1234/callback",
	}
	griffinClient := griffin.NewClient(clientCfg)
	err := griffinClient.Init()
	if err != nil {
		panic(err)
	}
	echoSp := griffinsp.NewEchoSupport(griffinClient)

	e := echo.New()

	e.GET("/", func(c echo.Context) error {
		return c.String(http.StatusOK, "Hello, World!")
	})

	e.GET("/login", echoSp.BuildLoginRequestHandler([]string{"openid", "profile", "email"}))

	e.GET("/callback", echoSp.BuildCallbackHandler(func(c echo.Context, tokenResponse *griffin.TokenExchangeResponse) error {
		accessTokenClaims, err := echoSp.Client.DecodeAccessToken(tokenResponse.AccessToken)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
		}
		userinfo, err := griffinClient.GetUserinfo(tokenResponse.AccessToken)
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
