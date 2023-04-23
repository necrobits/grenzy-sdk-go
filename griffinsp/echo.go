package griffinsp

import (
	"fmt"
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/necrobits/griffin-sdk-go/griffin"
)

type EchoCallbackFunc func(c echo.Context, tokenResponse *griffin.TokenExchangeResponse) error

type EchoSupport struct {
	oidc                *griffin.Client
	authParamCookieName string
}

func NewEchoSupport(oidcClient *griffin.Client) *EchoSupport {
	return &EchoSupport{
		oidc:                oidcClient,
		authParamCookieName: DefaultCookieName,
	}
}

func (ge *EchoSupport) SetAuthParamCookieName(name string) {
	ge.authParamCookieName = name
}

// HandleLoginRequest handles the login request.
// It will redirect the user to the login page if the user is not logged in.
// Just add this middleware to the route you want
// Example:
//
//	router.GET("/login",  echoSup.BuildLoginRequestHandler([]string{"openid", "profile", "email"}))
func (ge *EchoSupport) BuildLoginRequestHandler(scopes []string) echo.HandlerFunc {
	return func(c echo.Context) error {
		loginRequest, err := ge.oidc.GenerateLoginRequest(scopes)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, err)
		}
		// Store the auth verification params in a cookie
		cookie := griffin.MakeCookieForAuthVerificationParams(ge.authParamCookieName, loginRequest.AuthVerificationParams)
		c.SetCookie(cookie)
		// Redirect the user to the login page
		fmt.Printf("Redirecting to %s\n", loginRequest.AuthURL)
		return c.Redirect(http.StatusFound, loginRequest.AuthURL)
	}
}

// BuildCallbackHandler handles the callback request.
// It will handle the OIDC things and pass the token response to the user defined callback function.
// This allows more flexibility for the user to handle the token response.
// Example:
//
//	router.GET("/callback", ge.BuildCallbackHandler(func(c echo.Context, tokenResponse *griffin.TokenExchangeResponse) error {
//		userinfo, err := ge.oidc.GetUserInfo(tokenResponse.AccessToken)
//	}))
func (ge *EchoSupport) BuildCallbackHandler(cbFunc EchoCallbackFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		// Get the auth verification params from the cookie
		cookie, err := c.Cookie(ge.authParamCookieName)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, err)
		}
		authVerificationParams, err := griffin.GetAuthVerificationParamsFromCookie(cookie)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, err)
		}
		// Get the code and state from the query
		code := c.QueryParam("code")
		state := c.QueryParam("state")
		if code == "" || state == "" {
			return c.JSON(http.StatusBadRequest, "code or state is empty")
		}
		cbParams := &griffin.CallbackParams{
			Code:  code,
			State: state,
		}
		tokenResponse, err := ge.oidc.HandleLoginCallback(cbParams, authVerificationParams)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
		}
		// Pass the token response to the user defined callback function
		return cbFunc(c, tokenResponse)
	}
}
