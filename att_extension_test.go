package openid

import (
	"net/url"
	"testing"
)

func TestCreateAttributes(t *testing.T) {

	req := make(map[string]string)
	opt := make(map[string]string)

	req["one"] = "test:one"

	opt["two"] = "2"
	opt["three"] = "3"

	vals := RequestAttributes(&req, &opt)

	// for k, v := range *vals {
	// 	fmt.Printf("%v = %v\n", k, v)
	// }

	if vals.Get("openid.ns.ax") != "http://openid.net/srv/ax/1.0" {
		t.Errorf("Didn't set extension ns")
		return
	}

	if vals.Get("openid.ax.mode") != "fetch_request" {
		t.Errorf("Didn't set mode")
		return
	}

	if vals.Get("openid.ax.type.one") != req["one"] {
		t.Errorf("Failed to set a required attribute")
		return
	}

	if vals.Get("openid.ax.if_available") != "two,three" {
		t.Errorf("Failed to set the if_available attribute")
		return
	}
}

func TestParseAttributes(t *testing.T) {
	vals := url.Values{
		"openid.signed": []string{"assoc_handle,claimed_id,ext0.count.uid,ext0.mode,ext0.type.uid,ext0.value.uid.1,identity,mode,ns,ns.ext0,op_endpoint,response_nonce,return_to,signed"},

		"openid.op_endpoint":    []string{"https://www.exampe.com/oid/server"},
		"openid.response_nonce": []string{"2015-09-25T03:49:46ZmTvmDQ"},

		"openid.claimed_id": []string{"https://www.example.com/oid/id?claim=9f446a4aa5581c1ce61731918083aeb4425551ef"},

		"openid.ext0.count.uid":   []string{"1"},
		"openid.ext0.value.uid.1": []string{"123456"},
		"openid.identity":         []string{"https://www.example.com/oid/id?claim=9f446a4aa5581c1ce61731918083aeb4425551ef"},
		"openid.mode":             []string{"id_res"},
		"openid.ns.ext0":          []string{"http://openid.net/srv/ax/1.0"},
		"openid.sig":              []string{"61LnHEjZNABEwFFFlzkv4yVlFq8="},
		"openid.assoc_handle":     []string{"{HMAC-SHA1}{5884c45a}{TFFzMw==}"},
		"openid.ext0.type.uid":    []string{"http://openid.net/schema/person/guid"},
		"openid.ext0.mode":        []string{"fetch_response"},
		"openid.ns":               []string{"http://specs.openid.net/auth/2.0"},
	}

	atts, err := ParseAttributes("http://example.com/?" + vals.Encode())

	if err != nil {
		t.Errorf("Unexpected: %v", err)
		return
	}

	if (*atts)["uid"] != "123456" {
		t.Errorf("Didn't get the uid attribute")
		return
	}

}
