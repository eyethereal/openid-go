package openid

import (
	"net/url"
	"strings"
)

func RedirectURL(id, callbackURL, realm string) (string, error) {
	return redirectURL(id, callbackURL, realm, urlGetter, nil)
}

func RedirectURLWithExtraValues(id, callbackURL, realm string, extraValues *url.Values) (string, error) {
	return redirectURL(id, callbackURL, realm, urlGetter, extraValues)
}

func redirectURL(id, callbackURL, realm string, getter httpGetter, extraValues *url.Values) (string, error) {
	opEndpoint, opLocalID, claimedID, err := discover(id, getter)
	if err != nil {
		return "", err
	}
	return buildRedirectURL(opEndpoint, opLocalID, claimedID, callbackURL, realm, extraValues)
}

func buildRedirectURL(opEndpoint, opLocalID, claimedID, returnTo, realm string, extraValues *url.Values) (string, error) {
	values := make(url.Values)
	values.Add("openid.ns", "http://specs.openid.net/auth/2.0")
	values.Add("openid.mode", "checkid_setup")
	values.Add("openid.return_to", returnTo)

	if len(claimedID) > 0 {
		values.Add("openid.claimed_id", claimedID)
		if len(opLocalID) > 0 {
			values.Add("openid.identity", opLocalID)
		} else {
			values.Add("openid.identity",
				"http://specs.openid.net/auth/2.0/identifier_select")
		}
	} else {
		values.Add("openid.identity",
			"http://specs.openid.net/auth/2.0/identifier_select")
	}

	if len(realm) > 0 {
		values.Add("openid.realm", realm)
	}

	// Add in any extra values that might have been provided by the
	// original caller. These are likely part of an extension asking
	// for additional data
	encodedExtraValues := ""
	if extraValues != nil {
		encodedExtraValues = "&" + extraValues.Encode()
	}

	if strings.Contains(opEndpoint, "?") {
		return opEndpoint + "&" + values.Encode() + encodedExtraValues, nil
	}
	return opEndpoint + "?" + values.Encode() + encodedExtraValues, nil
}
