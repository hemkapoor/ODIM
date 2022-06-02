//(C) Copyright [2022] Hewlett Packard Enterprise Development LP
//
//Licensed under the Apache License, Version 2.0 (the "License"); you may
//not use this file except in compliance with the License. You may obtain
//a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
//Unless required by applicable law or agreed to in writing, software
//distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
//WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
//License for the specific language governing permissions and limitations
// under the License.

package licenses

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"

	dmtf "github.com/ODIM-Project/ODIM/lib-dmtf/model"
	"github.com/ODIM-Project/ODIM/lib-persistence-manager/persistencemgr"
	"github.com/ODIM-Project/ODIM/lib-utilities/common"
	licenseproto "github.com/ODIM-Project/ODIM/lib-utilities/proto/licenses"
	"github.com/ODIM-Project/ODIM/lib-utilities/response"
	lcommon "github.com/ODIM-Project/ODIM/svc-licenses/lcommon"
	"github.com/ODIM-Project/ODIM/svc-licenses/model"

	log "github.com/sirupsen/logrus"
)

// GetLicenseService to get license service details
func (e *ExternalInterface) GetLicenseService(req *licenseproto.GetLicenseServiceRequest) response.RPC {
	var resp response.RPC
	license := dmtf.LicenseService{
		OdataContext:   "/redfish/v1/$metadata#LicenseService.LicenseService",
		OdataID:        "/redfish/v1/LicenseService",
		OdataType:      "#LicenseService.v1_0_0.LicenseService",
		ID:             "LicenseService",
		Description:    "License Service",
		Name:           "License Service",
		ServiceEnabled: true,
	}
	license.Licenses = &dmtf.Link{Oid: "/redfish/v1/LicenseService/Licenses"}

	resp.Body = license
	resp.StatusCode = http.StatusOK
	return resp
}

// GetLicenseCollection to get license collection details
func (e *ExternalInterface) GetLicenseCollection(req *licenseproto.GetLicenseRequest) response.RPC {
	var resp response.RPC
	licenseCollection := dmtf.LicenseCollection{
		OdataContext: "/redfish/v1/$metadata#LicenseCollection.LicenseCollection",
		OdataID:      "/redfish/v1/LicenseService/Licenses",
		OdataType:    "#LicenseCollection.v1_0_0.LicenseCollection",
		Description:  "License Collection",
		Name:         "License Collection",
	}
	var members []*dmtf.Link

	licenseCollectionKeysArray, err := e.DB.GetAllKeysFromTable("Licenses", persistencemgr.InMemory)
	if err != nil || len(licenseCollectionKeysArray) == 0 {
		log.Error("odimra doesnt have Licenses")
		return common.GeneralError(http.StatusNotFound, response.ResourceNotFound, err.Error(), nil, nil)
	}

	for _, key := range licenseCollectionKeysArray {
		members = append(members, &dmtf.Link{Oid: key})
	}
	licenseCollection.Members = members
	licenseCollection.MembersCount = len(members)
	resp.Body = licenseCollection
	resp.StatusCode = http.StatusOK
	return resp
}

// GetLicenseResource to get individual license resource
func (e *ExternalInterface) GetLicenseResource(req *licenseproto.GetLicenseResourceRequest) response.RPC {
	var resp response.RPC
	licenseResp := dmtf.License{}
	uri := req.URL
	ID := strings.Split(uri, "/")

	data, dbErr := e.DB.GetResource("Licenses", uri, persistencemgr.InMemory)
	if dbErr != nil {
		log.Error("Unable to get license data : " + dbErr.Error())
		return common.GeneralError(http.StatusNotFound, response.ResourceNotFound, dbErr.Error(), nil, nil)
	}

	if data != "" {
		err := json.Unmarshal([]byte(data), &licenseResp)
		if err != nil {
			log.Error("Unable to unmarshall  the data: " + err.Error())
			return common.GeneralError(http.StatusInternalServerError, response.InternalError, err.Error(), nil, nil)
		}
	}
	licenseResp.OdataContext = "/redfish/v1/$metadata#License.License"
	licenseResp.OdataType = "#License.v1_0_0.License"
	licenseResp.OdataID = uri
	licenseResp.ID = ID[len(ID)-1]

	resp.Body = licenseResp
	resp.StatusCode = http.StatusOK
	return resp
}

type LicenseInstallRequest struct {
	LicenseString string             `json:"LicenseString,omitempty"`
	Links         *AuthorizedDevices `json:"Links,omitempty"`
}

type AuthorizedDevices struct {
	Link []*Link `json:"AuthorizedDevices,omitempty"`
}
type Link struct {
	Oid string `json:"@odata.id"`
}

func getManagerURL(systemURI string) ([]string, error) {
	var resource map[string]interface{}
	var managerLink string
	var links []string
	respData, err := lcommon.GetResource("ComputerSystem", systemURI, persistencemgr.InMemory)
	if err != nil {
		return nil, err
	}
	jerr := json.Unmarshal([]byte(respData), &resource)
	if jerr != nil {
		return nil, jerr
	}
	members := resource["Links"].(map[string]interface{})["ManagedBy"]
	log.Info("meemmberssss///////////////////", members)
	for _, member := range members.([]interface{}) {
		managerLink = member.(map[string]interface{})["@odata.id"].(string)
	}
	links = append(links, managerLink)
	log.Info("Linksssssssssssssss............", links)
	return links, nil
}

// UpdateLicenseResource to update license resource
func (e *ExternalInterface) UpdateLicenseResource(req *licenseproto.UpdateLicenseRequest) response.RPC {
	log.Info("in post command..................")
	var resp response.RPC
	var contactRequest model.PluginContactRequest
	var installreq LicenseInstallRequest
	log.Info("LLLLLLLLLLLLLLLLLLL", req)
	log.Info("1111111111111111111122222222222", req.RequestBody)
	genErr := json.Unmarshal(req.RequestBody, &installreq)
	if genErr != nil {
		errMsg := "Unable to unmarshal the install license request" + genErr.Error()
		log.Error(errMsg)
		return common.GeneralError(http.StatusBadRequest, response.InternalError, errMsg, nil, nil)
	}
	log.Info("11111111111111111111", installreq)
	var serverURI, managerID string
	var err error
	var managerLink []string
	linksMap := make(map[string]bool)
	for _, serverIDs := range installreq.Links.Link {
		serverURI = serverIDs.Oid
		if strings.Contains(serverURI, "Systems") {
			managerLink, err = getManagerURL(serverURI)
			if err != nil {
				errMsg := "Unable to get System resource"
				log.Error(errMsg)
				return common.GeneralError(http.StatusInternalServerError, response.InternalError, errMsg, nil, nil)
			}
			for _, link := range managerLink {
				linksMap[link] = true
			}
		} else if strings.Contains(serverURI, "Managers") {
			linksMap[serverURI] = true
		} else {
			errMsg := "Invalid AuthorizedDevices links"
			log.Error(errMsg)
			return common.GeneralError(http.StatusBadRequest, response.InternalError, errMsg, nil, nil)
		}
	}
	log.Info(">>>>>>>>>>>>>>>>>map link", linksMap)

	for serverURI := range linksMap {
		log.Info("serverURI....................", serverURI)
		uuid, _, err := lcommon.GetIDsFromURI(serverURI)
		if err != nil {
			errMsg := "error while trying to get system ID from " + serverURI + ": " + err.Error()
			log.Error(errMsg)
			return common.GeneralError(http.StatusNotFound, response.ResourceNotFound, errMsg, []interface{}{"SystemID", serverURI}, nil)
		}
		log.Info("uuuuuuuuuuuuiiiiiiiiiiiiiidddddddddddd", uuid)
		// Get target device Credentials from using device UUID
		target, targetErr := lcommon.GetTarget(uuid)
		if targetErr != nil {
			errMsg := err.Error()
			log.Error(errMsg)
			return common.GeneralError(http.StatusNotFound, response.ResourceNotFound, errMsg, []interface{}{"target", uuid}, nil)
		}
		log.Info("target.................", target)
		decryptedPasswordByte, err := e.External.DevicePassword(target.Password)
		if err != nil {
			errMsg := "error while trying to decrypt device password: " + err.Error()
			log.Error(errMsg)
			return common.GeneralError(http.StatusInternalServerError, response.InternalError, errMsg, nil, nil)
		}
		log.Info("decrytpt pass.............................", decryptedPasswordByte)
		target.Password = decryptedPasswordByte

		// Get the Plugin info
		plugin, errs := lcommon.GetPluginData(target.PluginID)
		if errs != nil {
			errMsg := "error while getting plugin data: " + errs.Error()
			log.Error(errMsg)
			return common.GeneralError(http.StatusNotFound, response.ResourceNotFound, errMsg, []interface{}{"PluginData", target.PluginID}, nil)
		}
		log.Info("Pluginnnnnnnnnnn....................", plugin)
		encodedKey := base64.StdEncoding.EncodeToString([]byte(installreq.LicenseString))
		managerURL := "/redfish/v1/Managers/" + managerID
		reqPostBody := map[string]interface{}{"LicenseString": encodedKey, "AuthorizedDevices": managerURL}
		reqBody, _ := json.Marshal(reqPostBody)

		contactRequest.Plugin = *plugin
		contactRequest.ContactClient = e.External.ContactClient
		contactRequest.Plugin.ID = target.PluginID
		contactRequest.HTTPMethodType = http.MethodPost

		if strings.EqualFold(plugin.PreferredAuthType, "XAuthToken") {
			log.Info("insideee.............")
			contactRequest.DeviceInfo = map[string]interface{}{
				"UserName": plugin.Username,
				"Password": string(plugin.Password),
			}
			contactRequest.OID = "/ODIM/v1/Sessions"
			_, token, getResponse, err := lcommon.ContactPlugin(contactRequest, "error while logging in to plugin: ")
			if err != nil {
				errMsg := err.Error()
				log.Error(errMsg)
				return common.GeneralError(getResponse.StatusCode, getResponse.StatusMessage, errMsg, getResponse.MsgArgs, nil)
			}
			log.Info("resppppppppppppppppppppp.....................", getResponse)
			contactRequest.Token = token
		} else {
			log.Info("hereeee....................")
			contactRequest.LoginCredentials = map[string]string{
				"UserName": plugin.Username,
				"Password": string(plugin.Password),
			}

		}
		target.PostBody = []byte(reqBody)
		contactRequest.DeviceInfo = target
		contactRequest.OID = "/ODIM/v1/LicenseService/Licenses"
		contactRequest.PostBody = reqBody
		body, _, getResponse, err := e.External.ContactPlugin(contactRequest, "error while installing license: ")
		if err != nil {
			errMsg := err.Error()
			log.Error(errMsg)
			return common.GeneralError(getResponse.StatusCode, getResponse.StatusMessage, errMsg, getResponse.MsgArgs, nil)
		}
		log.Info("RESPPPPPPPPPPPPPPPPPPPPPPPPP!!!!!!!!!!!!!!!!", body)
	}

	//resp.Body = body
	resp.StatusCode = http.StatusOK
	return resp
}
