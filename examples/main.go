package main

import (
	"encoding/base64"
	"encoding/json"
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/necrobits/griffin-sdk-go/griffin"
)

func mustMarshalJSON(v interface{}) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(b)
}

func mustUnmarshalJSON(s string, v interface{}) {
	err := json.Unmarshal([]byte(s), v)
	if err != nil {
		panic(err)
	}
}

func main() {
	clientCfg := &griffin.OidcClientConfig{
		ClientID:          "clientid",
		ClientSecret:      "clientsecret",
		Domain:            "localhost:1234",
		GriffinURL:        "http://localhost:4000",
		GriffinBackendURL: "http://localhost:8080",
		RedirectURL:       "http://localhost:1234/callback",
	}
	griffinClient := griffin.NewOidcClient(clientCfg)
	err := griffinClient.Init()
	if err != nil {
		panic(err)
	}
	e := echo.New()

	e.GET("/", func(c echo.Context) error {
		return c.String(http.StatusOK, "Hello, World!")
	})

	e.GET("/login", func(c echo.Context) error {
		loginRequest, err := griffinClient.GenerateLoginRequest([]string{"openid", "profile", "email"})
		if err != nil {
			return c.JSON(http.StatusInternalServerError, err)
		}
		jsonVal := mustMarshalJSON(loginRequest.AuthVerificationParams)
		cookieVal := base64.RawURLEncoding.EncodeToString([]byte(jsonVal))
		c.SetCookie(&http.Cookie{
			Name:     "griffin_auth",
			Path:     "/",
			Value:    cookieVal,
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
		})
		print("AuthURL: ", loginRequest.AuthURL)
		return c.Redirect(http.StatusFound, loginRequest.AuthURL)
	})

	e.GET("/callback", func(c echo.Context) error {
		code := c.QueryParam("code")
		state := c.QueryParam("state")
		cbParams := &griffin.CallbackParams{
			Code:  code,
			State: state,
		}
		cookie, err := c.Cookie("griffin_auth")
		cookieBytes, err := base64.RawURLEncoding.DecodeString(cookie.Value)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
		}
		var authVerificationParams griffin.AuthVerificationParams
		mustUnmarshalJSON(string(cookieBytes[:]), &authVerificationParams)

		tokenResponse, err := griffinClient.HandleLoginCallback(cbParams, &authVerificationParams)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
		}
		userinfo, err := griffinClient.GetUserInfo(tokenResponse.AccessToken)

		resp := map[string]interface{}{
			"tokenResponse": tokenResponse,
			"userinfo":      userinfo,
		}
		return c.JSON(http.StatusOK, resp)
	})

	e.Logger.Fatal(e.Start(":1234"))
}
