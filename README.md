# GriffinID SDK for Golang

You can use the SDK to integrate your Golang application with GriffinID, using the PKCE flow.

The SDK can be used independently, or you can integrate it with your favorite web framework using the `griffinsp` package.

Currently support OpenID Connect (OIDC) only.

## Getting started

Get the SDK

```
go get -u github.com/necrobits/griffin-sdk-go
```

Create a new GriffinID client

```golang
import (
    "github.com/necrobits/griffin-sdk-go/griffin"
)

//...

clientCfg := &griffin.ClientConfig{
    ClientID:          "clientid",
    ClientSecret:      "clientsecret",
    GriffinURL:        "http://localhost:3000",
    OidcRedirectURL:   "http://localhost:3001/callback",
}
griffinClient := griffin.NewClient(clientCfg)
// Call the InitOidc method to initialize the client.
// This method retrieves the OpenID configuration from the GriffinID server.
err := griffinClient.Init()
```

## Supported frameworks

### Echo

Create the support object

```golang
import (
    "github.com/necrobits/griffin-sdk-go/griffinsp"
)
// ...
echoSp := griffinsp.NewEchoSupport(griffinClient)
```

Handle the login request

```golang
router.GET("/login", echoSp.BuildLoginHandler([]string{"openid", "profile", "email"}))
```

Handle the callback request

```golang
router.GET("/callback", echoSp.BuildCallbackHandler(func(c echo.Context, tokenResponse *griffin.TokenExchangeResponse) error {
    userinfo, err := echoSp.Client.GetUserInfo(tokenResponse.AccessToken)
    // ...
}))
```

### Gin

Tbd.

## License

MIT © [Necrobits](https://github.com/necrobits)
