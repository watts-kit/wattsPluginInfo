package main

import (
	"encoding/json"
	l "git.scc.kit.edu/lukasburgey/wattsPluginLib"
	"github.com/kalaspuffar/base64url"
)

var keyToName = map[string]string{
	"iss":    "Issuer",
	"sub":    "Subject",
	"name":   "Name",
	"groups": "Groups",
	"email":  "E-Mail",
	"gender": "Gender",
}

func request(pi l.Input) l.Output {
	uidDecoded, err := base64url.Decode(pi.WaTTSUserID)
	l.Check(err, 1, "could not decode WaTTSUserID")

	credential := []l.Credential{
		l.Credential{"name": "WaTTS version", "type": "text", "value": pi.WaTTSVersion},
		l.Credential{"name": "WaTTS userid", "type": "text", "value": pi.WaTTSUserID},
		l.Credential{"name": "WaTTS userid (decoded)", "type": "text", "value": string(uidDecoded)},
	}

	for key, value := range pi.UserInfo {
		credType := "text"
		if key == "groups" {
			credType = "textarea"
		}

		bs, err := json.Marshal(value)
		l.Check(err, 1, "unable to marshal user info key "+key)

		credential = append(
			credential,
			l.Credential{
				"name":  keyToName[key],
				"type":  credType,
				"value": string(bs),
			})
	}

	return l.PluginGoodRequest(credential, "user_info")
}

func revoke(pi l.Input) l.Output {
	return l.PluginGoodRevoke()
}

func main() {
	pluginDescriptor := l.PluginDescriptor{
		Version:     "0.1.0",
		Author:      "Lukas Burgey @ KIT within the INDIGO DataCloud Project",
		Name:        "wattsPluginInfo",
		Description: "A watts plugin to get infos about the",
		Actions: map[string]l.Action{
			"request": request,
			"revoke":  revoke,
		},
		ConfigParams:  []l.ConfigParamsDescriptor{},
		RequestParams: []l.RequestParamsDescriptor{},
	}
	l.PluginRun(pluginDescriptor)
}
