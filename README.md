# GrenzyID SDK for Golang

You can use the SDK to integrate your Golang application with GrenzyID, using the PKCE flow.

The SDK can be used independently, or you can integrate it with your favorite web framework using the `grenzysp` package.

Currently support OpenID Connect (OIDC) only.

## Getting started

Get the SDK

```
go get -u github.com/necrobits/grenzy-sdk-go
```

Create a new GrenzyID client

```golang
import (
    "github.com/necrobits/grenzy-sdk-go/grenzy"
)

//...

clientCfg := &grenzy.ClientConfig{
    ClientID:          "clientid",
    ClientSecret:      "clientsecret",
    GrenzyURL:        "http://localhost:3000",
    OidcRedirectURL:   "http://localhost:3001/callback",
}
grenzyClient := grenzy.NewClient(clientCfg)
// Call the InitOidc method to initialize the client.
// This method retrieves the OpenID configuration from the GrenzyID server.
err := grenzyClient.Init()
```

## Supported frameworks

### Echo

Create the support object

```golang
import (
    "github.com/necrobits/grenzy-sdk-go/grenzysp"
)
// ...
echoSp := grenzysp.NewEchoSupport(grenzyClient)
```

Handle the login request

```golang
router.GET("/login", echoSp.BuildLoginHandler([]string{"openid", "profile", "email"}))
```

Handle the callback request

```golang
router.GET("/callback", echoSp.BuildCallbackHandler(func(c echo.Context, tokenResponse *grenzy.TokenExchangeResponse) error {
    userinfo, err := echoSp.Client.GetUserInfo(tokenResponse.AccessToken)
    // ...
}))
```

### Gin

Tbd.

## License

MIT © [Necrobits](https://github.com/necrobits)
