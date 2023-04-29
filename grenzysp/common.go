package grenzysp

const (
	// CookieName is the name of the cookie that stores the auth verification params
	DefaultCookieName = "grenzy_auth"
)

func makeErrorObject(err error) map[string]interface{} {
	return map[string]interface{}{
		"error": err.Error(),
	}
}
