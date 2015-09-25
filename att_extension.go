package openid

import (
	"errors"
	"net/url"
	"strings"
)

// Returns a pointer to a url.Values object which can be passed to RedirectURLWithExtraValues
// to query for additional user attributes using the openid attribute exchange 1.0 extension.
//
// The maps for required or optional attributes map an alias to a URI for the value. The alias
// should be something short that conforms to the openid rules about aliases (basically no
// periods and can't conflict with reserved words). Listed below are some common general
// properties that might be interesting.
//
// This alias assigned when requesting the attribute is the alias that can be used to find
// the attribute when it is returned.
//
// The protcol allows for requesting a limited number of returned values, but that is not
// implemented here.
//
// Learn more at https://openid.net/specs/openid-attribute-exchange-1_0.html and
// https://openid.net/specs/openid-attribute-properties-list-1_0-01.html
//
// Here's a list of the obsolete schema values: http://stackoverflow.com/questions/7403536/list-of-available-attributes-for-http-axschema-org-and-http-schemas-openid-n
/*
   http://openid.net/schema/namePerson/prefix
   http://openid.net/schema/namePerson/first
   http://openid.net/schema/namePerson/last
   http://openid.net/schema/namePerson/middle
   http://openid.net/schema/namePerson/suffix
   http://openid.net/schema/namePerson/friendly
   http://openid.net/schema/person/guid
   http://openid.net/schema/birthDate/birthYear
   http://openid.net/schema/birthDate/birthMonth
   http://openid.net/schema/birthDate/birthday
   http://openid.net/schema/gender
   http://openid.net/schema/language/pref
   http://openid.net/schema/contact/phone/default
   http://openid.net/schema/contact/phone/home
   http://openid.net/schema/contact/phone/business
   http://openid.net/schema/contact/phone/cell
   http://openid.net/schema/contact/phone/fax
   http://openid.net/schema/contact/postaladdress/home
   http://openid.net/schema/contact/postaladdressadditional/home
   http://openid.net/schema/contact/city/home
   http://openid.net/schema/contact/state/home
   http://openid.net/schema/contact/country/home
   http://openid.net/schema/contact/postalcode/home
   http://openid.net/schema/contact/postaladdress/business
   http://openid.net/schema/contact/postaladdressadditional/business
   http://openid.net/schema/contact/city/business
   http://openid.net/schema/contact/state/business
   http://openid.net/schema/contact/country/business
   http://openid.net/schema/contact/postalcode/business
   http://openid.net/schema/contact/IM/default
   http://openid.net/schema/contact/IM/AIM
   http://openid.net/schema/contact/IM/ICQ
   http://openid.net/schema/contact/IM/MSN
   http://openid.net/schema/contact/IM/Yahoo
   http://openid.net/schema/contact/IM/Jabber
   http://openid.net/schema/contact/IM/Skype
   http://openid.net/schema/contact/internet/email
   http://openid.net/schema/contact/web/default
*/
func RequestAttributes(required *map[string]string, optional *map[string]string) *url.Values {

	values := make(url.Values)

	values.Add("openid.ns.ax", "http://openid.net/srv/ax/1.0")
	values.Add("openid.ax.mode", "fetch_request")

	if required != nil {
		required_list := ""
		for alias, uri := range *required {
			values.Add("openid.ax.type."+alias, uri)
			if len(required_list) > 0 {
				required_list += ","
			}
			required_list += alias
		}
		if len(required_list) > 0 {
			values.Add("openid.ax.required", required_list)
		}
	}

	if optional != nil {
		optional_list := ""
		for alias, uri := range *optional {
			values.Add("openid.ax.type."+alias, uri)
			if len(optional_list) > 0 {
				optional_list += ","
			}
			optional_list += alias
		}
		if len(optional_list) > 0 {
			values.Add("openid.ax.if_available", optional_list)
		}
	}

	// values.Add("openid.ax.type.uid", "http://openid.net/schema/person/guid")
	// values.Add("openid.ax.required", "uid")

	return &values
}

// Takes a full uri with a query string attached and parses out values that have been
// returned from the attribute extension. These are filled out into the returned map using
// the aliases that were configured when RequestAttributes was called. The values in the
// map are the values of the attributes.
//
// Since multi-value attributes are not supported in RequestAttributes, the are similarly
// not supported here. However, because some servers will return single values using the
// count method with a count of 1, if this is the case, then the first value will be
// returned and the others will be ignored.
func ParseAttributes(uri string) (*map[string]string, error) {
	parsedURL, err := url.Parse(uri)
	if err != nil {
		return nil, err
	}
	values, err := url.ParseQuery(parsedURL.RawQuery)
	if err != nil {
		return nil, err
	}

	// Find a namespace alias
	alias := ""
	for k, v := range values {
		// fmt.Printf("%v = %v\n", k, v)

		if strings.HasPrefix(k, "openid.ns.") && len(v) == 1 && v[0] == "http://openid.net/srv/ax/1.0" {
			alias = k[10:len(k)]
			break
		}
	}
	if len(alias) == 0 {
		return nil, errors.New("Did not find an alias for the attribute extension")
	}

	v := values["openid."+alias+".mode"]
	if v == nil || len(v) != 1 || v[0] != "fetch_response" {
		return nil, errors.New("The extension mode is not fetch_response")
	}

	// Look at all the values
	out := make(map[string]string)
	vPfx := "openid." + alias + ".value."
	for k, v := range values {
		if strings.HasPrefix(k, vPfx) {
			// It is one of our values. Extract it's alias
			vAlias := k[len(vPfx):len(k)]
			ix := strings.IndexByte(vAlias, '.')
			if ix != -1 {
				// If this is .1 then we take it, otherwise we ignore it
				if !strings.HasSuffix(vAlias, ".1") {
					continue
				}

				vAlias = vAlias[:ix]
			}

			out[vAlias] = v[0]
		}
	}

	return &out, nil
}
