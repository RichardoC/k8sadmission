/*
Copyright (C) 2023 Richard Tweed.
Copyright (C) 2022 The Falco Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package k8sadmission

import (
	"fmt"
	"io"
	"io/ioutil"
	"strings"

	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
	"github.com/valyala/fastjson"
)

const (
	noIndexFilter = -1
)

var (
	// ErrExtractNotAvailable indicates that the requested field cannot be
	// extracted from a certain event due to some value not being available
	// inside the event.
	ErrExtractNotAvailable = fmt.Errorf("field not available")
	//
	// ErrExtractWrongType indicates that the requested field cannot be
	// extracted from a certain event due to some value having an unexpected
	// type inside the event.
	ErrExtractWrongType = fmt.Errorf("wrong type conversion")
	//
	// ErrExtractBrokenJSON indicates that the requested field cannot be
	// extracted from a certain event due to the internal JSON prepresentaiton
	// being broken or badly formatted
	ErrExtractBrokenJSON = fmt.Errorf("broken JSON data")
	//
	// ErrExtractUnsupportedType indicates that the requested field cannot be
	// extracted from a certain event due to its field type being not supported
	ErrExtractUnsupportedType = fmt.Errorf("type not supported")
)

func (k *Plugin) Extract(req sdk.ExtractRequest, evt sdk.EventReader) error {
	err := k.ExtractFromEvent(req, evt)
	// We want to keep not-available errors internal. Propagating
	// this error is useful to implement a clean extraction logic, however
	// this kind of error would be very noisy for the framework and is not
	// truly relevant. Plus, the plugin framework understands that a field
	// is not present by checking that sdk.ExtractRequest.SetValue() has not
	// being invoked.
	if err == ErrExtractNotAvailable {
		return nil
	}
	return err
}

// Decode parses a JSON value from an io.ReadSeeker
func (e *Plugin) DecodeReader(evtNum uint64, reader io.ReadSeeker) (*fastjson.Value, error) {
	// as a very quick sanity check, only try to extract all if
	// the first character is '{'
	data := []byte{0}
	_, err := reader.Read(data)
	if err != nil {
		return nil, err
	}
	if !(data[0] == '{') {
		return nil, ErrExtractBrokenJSON
	}
	// decode the json, but only if we haven't done it yet for this event
	// if evtNum != e.jdataEvtnum {
	{
		_, err := reader.Seek(0, io.SeekStart)
		if err != nil {
			return nil, err
		}
		data, err = ioutil.ReadAll(reader)
		if err != nil {
			return nil, err
		}
		e.jdata, err = e.jparser.ParseBytes(data)
		if err != nil {
			return nil, err
		}
		e.jdataEvtnum = evtNum
	}
	return e.jdata, nil
}

// DecodeEvent parses a JSON value from a sdk.EventReader
func (e *Plugin) DecodeEvent(evt sdk.EventReader) (*fastjson.Value, error) {
	return e.DecodeReader(evt.EventNum(), evt.Reader())
}

// ExtractFromEvent processes a sdk.ExtractRequest and extracts a
// field by reading data from a sdk.EventReader
func (e *Plugin) ExtractFromEvent(req sdk.ExtractRequest, evt sdk.EventReader) error {
	jsonValue, err := e.DecodeEvent(evt)
	if err != nil {
		return err
	}
	return e.ExtractFromJSON(req, jsonValue)
}

// ExtractFromJSON processes a sdk.ExtractRequest and extracts a
// field by reading data from a jsonValue *fastjson.Value
func (e *Plugin) ExtractFromJSON(req sdk.ExtractRequest, jsonValue *fastjson.Value) error {
	// discard unrelated JSONs events
	if jsonValue.Get("request", "uid") == nil {
		return ErrExtractNotAvailable
	}
	switch req.Field() {
	case "kar.uid":
		return e.extractFromKeys(req, jsonValue, "request", "uid")
	// case "kar.stage": // Not relevant for admission review
	// 	return e.extractFromKeys(req, jsonValue, "stage")
	case "kar.timestamp":
		return e.extractFromKeys(req, jsonValue, "requestReceivedTimestamp")
	case "kar.dry-run":
		return e.extractFromKeys(req, jsonValue, "request", "dryRun")
	// case "kar.auth.decision":
	// 	return e.extractFromKeys(req, jsonValue, "annotations", "authorization.k8s.io/decision")
	// case "kar.auth.reason":
	// 	return e.extractFromKeys(req, jsonValue, "annotations", "authorization.k8s.io/reason")
	case "kar.user.name":
		return e.extractFromKeys(req, jsonValue, "request", "userInfo", "username")
	case "kar.user.groups":
		return e.extractFromKeys(req, jsonValue, "request", "userInfo", "groups")
	// Not sure if possible
	// case "kar.impuser.name":
	// 	return e.extractFromKeys(req, jsonValue, "impersonatedUser", "username")

	// The k8saudit plugin sets this as lower case but this should be uppercase to match
	// k8s docs, and we'll match the k8s docs
	case "kar.verb":
		return e.extractFromKeys(req, jsonValue, "request", "operation")
	// case "kar.uri":
	// 	return e.extractFromKeys(req, jsonValue, "requestURI")
	// case "kar.uri.param":
	// 	uriValue := jsonValue.Get("requestURI")
	// 	if uriValue == nil {
	// 		return ErrExtractNotAvailable
	// 	}
	// 	uriString, err := e.jsonValueAsString(uriValue)
	// 	if err != nil {
	// 		return err
	// 	}
	// 	uri, err := url.Parse(uriString)
	// 	if err != nil {
	// 		return err
	// 	}
	// 	query, err := url.ParseQuery(uri.RawQuery)
	// 	if err != nil {
	// 		return err
	// 	}
	// 	param := query[req.ArgKey()]
	// 	if len(param) > 0 {
	// 		req.SetValue(param[0])
	// 	}
	case "kar.target.name":
		return e.extractFromKeys(req, jsonValue, "request", "name")
	case "kar.target.namespace":
		return e.extractFromKeys(req, jsonValue, "request", "namespace")
	case "kar.target.resource":
		return e.extractFromKeys(req, jsonValue, "request", "resource", "resource")
	case "kar.target.subresource":
		return e.extractFromKeys(req, jsonValue, "request", "subResource")
	case "kar.req.binding.subjects":
		return e.extractFromKeys(req, jsonValue, "request", "object", "subjects")
	case "kar.req.binding.role":
		return e.extractFromKeys(req, jsonValue, "request", "object", "roleRef", "name")
	// Feels unneeded given kar.target.name
	case "kar.req.configmap.name":
		return e.extractFromKeys(req, jsonValue, "request", "name")
	case "kar.req.configmap.data":
		return e.extractFromKeys(req, jsonValue, "request", "object", "binaryData")
	case "kar.req.configmap.binary_data":
		return e.extractFromKeys(req, jsonValue, "request", "object", "data")

	// TODO actually have these work on image registries
	case "kar.req.pod.containers.image":
		indexFilter := e.argIndexFilter(req)
		images, err := e.readContainerImages(jsonValue, indexFilter)
		if err != nil {
			return err
		}
		req.SetValue(images)
	case "kar.req.pod.containers.image.repository":
		indexFilter := e.argIndexFilter(req)
		repos, err := e.readContainerRepositories(jsonValue, indexFilter)
		if err != nil {
			return err
		}
		req.SetValue(repos)
	// case "kar.req.container.image":
	// 	images, err := e.readContainerImages(jsonValue, 0)
	// 	if err != nil {
	// 		return err
	// 	}
	// 	req.SetValue(images[0])
	// case "kar.req.container.image.repository":
	// 	repos, err := e.readContainerRepositories(jsonValue, 0)
	// 	if err != nil {
	// 		return err
	// 	}
	// 	req.SetValue(repos[0])
	//
	// TODO: check if the following works
	case "kar.req.pod.host_ipc":
		return e.extractFromKeys(req, jsonValue, "request", "object", "spec", "hostIPC")
	case "kar.req.pod.host_network":
		return e.extractFromKeys(req, jsonValue, "request", "object", "spec", "hostNetwork")
	// case "kar.req.container.host_network":
	// 	return e.extractFromKeys(req, jsonValue, "request", "object", "spec", "hostNetwork")
	case "kar.req.pod.host_pid":
		return e.extractFromKeys(req, jsonValue, "request", "object", "spec", "hostPID")
	// to fix?
	case "kar.req.pod.containers.host_port":
		indexFilter := e.argIndexFilter(req)
		values, err := e.readContainerHostPorts(jsonValue, indexFilter)
		if err != nil {
			return err
		}
		req.SetValue(values)
	//  to fix?
	case "kar.req.pod.containers.privileged":
		arr, err := e.getValuesRecursive(jsonValue, e.argIndexFilter(req), "request", "object", "spec", "containers", "securityContext", "privileged")
		if err != nil {
			return err
		}
		req.SetValue(e.arrayAsStringsSkipNil(arr))
	case "kar.req.exec.command":
		return e.extractFromKeys(req, jsonValue, "request", "object", "command")
	// case "kar.req.container.privileged":
	// 	arr, err := e.getValuesRecursive(jsonValue, noIndexFilter, "request", "object", "spec", "containers", "securityContext", "privileged")
	// 	if err != nil {
	// 		return err
	// 	}
	// 	for _, priv := range arr {
	// 		if priv != nil && priv.GetBool() {
	// 			req.SetValue("true")
	// 			return nil
	// 		}
	// 	}
	// 	req.SetValue("false")
	case "kar.req.pod.containers.allow_privilege_escalation":
		arr, err := e.getValuesRecursive(jsonValue, e.argIndexFilter(req), "request", "object", "spec", "containers", "securityContext", "allowPrivilegeEscalation")
		if err != nil {
			return err
		}
		req.SetValue(e.arrayAsStringsSkipNil(arr))
	case "kar.req.pod.containers.read_only_fs":
		arr, err := e.getValuesRecursive(jsonValue, e.argIndexFilter(req), "request", "object", "spec", "containers", "securityContext", "readOnlyRootFilesystem")
		if err != nil {
			return err
		}
		req.SetValue(e.arrayAsStringsSkipNil(arr))
	case "kar.req.pod.run_as_user":
		return e.extractFromKeys(req, jsonValue, "request", "object", "spec", "securityContext", "runAsUser")
	case "kar.req.pod.containers.run_as_user":
		arr, err := e.getValuesRecursive(jsonValue, e.argIndexFilter(req), "request", "object", "spec", "containers", "securityContext", "runAsUser")
		if err != nil {
			return err
		}
		req.SetValue(e.arrayAsStringsSkipNil(arr))
	case "kar.req.pod.containers.eff_run_as_user":
		indexFilter := e.argIndexFilter(req)
		values, err := e.readFromContainerEffectively(jsonValue, indexFilter, "runAsUser")
		if err != nil {
			return err
		}
		req.SetValue(values)
	case "kar.req.pod.run_as_group":
		return e.extractFromKeys(req, jsonValue, "request", "object", "spec", "securityContext", "runAsGroup")
	case "kar.req.pod.containers.run_as_group":
		arr, err := e.getValuesRecursive(jsonValue, e.argIndexFilter(req), "request", "object", "spec", "containers", "securityContext", "runAsGroup")
		if err != nil {
			return err
		}
		req.SetValue(e.arrayAsStringsSkipNil(arr))
	case "kar.req.pod.containers.eff_run_as_group":
		indexFilter := e.argIndexFilter(req)
		values, err := e.readFromContainerEffectively(jsonValue, indexFilter, "runAsGroup")
		if err != nil {
			return err
		}
		req.SetValue(values)
	case "kar.req.pod.containers.proc_mount":
		arr, err := e.getValuesRecursive(jsonValue, e.argIndexFilter(req), "request", "object", "spec", "containers", "securityContext", "procMount")
		if err != nil {
			return err
		}
		req.SetValue(e.arrayAsStringsSkipNil(arr))
	case "kar.req.role.rules":
		return e.extractFromKeys(req, jsonValue, "request", "object", "rules")
	case "kar.req.role.rules.apiGroups":
		return e.extractRulesField(req, jsonValue, "apiGroups")
	case "kar.req.role.rules.nonResourceURLs":
		return e.extractRulesField(req, jsonValue, "nonResourceURLs")
	case "kar.req.role.rules.verbs":
		return e.extractRulesField(req, jsonValue, "verbs")
	case "kar.req.role.rules.resources":
		return e.extractRulesField(req, jsonValue, "resources")
	case "kar.req.pod.fs_group":
		return e.extractFromKeys(req, jsonValue, "request", "object", "spec", "securityContext", "fsGroup")
	case "kar.req.pod.supplemental_groups":
		return e.extractFromKeys(req, jsonValue, "request", "object", "spec", "securityContext", "supplementalGroups")
	case "kar.req.pod.containers.add_capabilities":
		arr, err := e.getValuesRecursive(jsonValue, e.argIndexFilter(req), "request", "object", "spec", "containers", "securityContext", "capabilities", "add")
		if err != nil {
			return err
		}
		req.SetValue(e.arrayAsStringsSkipNil(arr))
	case "kar.req.service.type":
		return e.extractFromKeys(req, jsonValue, "request", "object", "spec", "type")
	case "kar.req.service.ports":
		indexFilter := e.argIndexFilter(req)
		arr, err := e.getValuesRecursive(jsonValue, indexFilter, "request", "object", "spec", "ports")
		if err != nil {
			return err
		}
		req.SetValue(e.arrayAsStringsSkipNil(arr))
	case "kar.req.volume.hostpath":
		arr, err := e.getValuesRecursive(jsonValue, e.argIndexFilter(req), "request", "object", "spec", "volumes", "hostPath", "path")
		if err != nil {
			return err
		}

		// if the index key ends with a *, do a prefix match.
		// Otherwise, compare for equality.
		arg := req.ArgKey()
		isPrefixSearch := strings.HasSuffix(arg, "*")
		prefixSearch := arg[:len(arg)-1]
		for _, v := range e.arrayAsStringsSkipNil(arr) {
			if isPrefixSearch && strings.HasPrefix(v, prefixSearch) || arg == v {
				req.SetValue("true")
				return nil
			}
		}
		req.SetValue("false")
	case "kar.req.pod.volumes.hostpath":
		arr, err := e.getValuesRecursive(jsonValue, e.argIndexFilter(req), "request", "object", "spec", "volumes", "hostPath", "path")
		if err != nil {
			return err
		}
		req.SetValue(e.arrayAsStringsSkipNil(arr))
	case "kar.req.pod.volumes.flexvolume_driver":
		arr, err := e.getValuesRecursive(jsonValue, e.argIndexFilter(req), "request", "object", "spec", "volumes", "flexVolume", "driver")
		if err != nil {
			return err
		}
		req.SetValue(e.arrayAsStringsSkipNil(arr))
	case "kar.req.pod.volumes.volume_type":
		indexFilter := e.argIndexFilter(req)
		arr, err := e.getValuesRecursive(jsonValue, indexFilter, "request", "object", "spec", "volumes", "")
		if err != nil {
			return err
		}
		var values []string
		// note(jasondellaluce): this has been implemented just like in the
		// original K8S Audit, but I'm not sure this works as intended
		for _, v := range arr {
			if v.Type() == fastjson.TypeObject {
				obj, err := v.Object()
				if err != nil {
					return err
				}
				obj.Visit(func(key []byte, v *fastjson.Value) {
					if string(key) != "name" {
						values = append(values, string(key))
					}
				})
			}
		}
		req.SetValue(values)
	case "kar.resp.name":
		return e.extractFromKeys(req, jsonValue, "responseObject", "metadata", "name")
	case "kar.response.code":
		return e.extractFromKeys(req, jsonValue, "responseStatus", "code")
	case "kar.response.reason":
		return e.extractFromKeys(req, jsonValue, "responseStatus", "reason")
	case "kar.useragent":
		return e.extractFromKeys(req, jsonValue, "userAgent")
	case "kar.sourceips":
		return e.extractRulesField(req, jsonValue, "sourceIPs")
	default:
		return fmt.Errorf("unsupported extraction field: %s", req.Field())
	}
	return nil
}

func (e *Plugin) argIndexFilter(req sdk.ExtractRequest) int {
	if !req.ArgPresent() {
		return noIndexFilter
	}
	return int(req.ArgIndex())
}

func (e *Plugin) getValuesRecursive(jsonValue *fastjson.Value, indexFilter int, keys ...string) ([]*fastjson.Value, error) {
	for i, k := range keys {
		if jsonValue.Type() == fastjson.TypeArray {
			if indexFilter == noIndexFilter {
				var res []*fastjson.Value
				for _, v := range jsonValue.GetArray() {
					vals, err := e.getValuesRecursive(v, indexFilter, keys[i:]...)
					if err == nil {
						res = append(res, vals...)
					} else if err == ErrExtractNotAvailable {
						res = append(res, nil)
					} else {
						return nil, err
					}
				}
				return res, nil
			}
			arr := jsonValue.GetArray()
			if arr == nil || indexFilter >= len(arr) {
				return nil, ErrExtractNotAvailable
			}
			jsonValue = arr[indexFilter]
		}

		if len(k) > 0 {
			jsonValue = jsonValue.Get(k)
		} else {
			jsonValue = jsonValue.Get()
		}
		if jsonValue == nil {
			return nil, ErrExtractNotAvailable
		}
	}
	return []*fastjson.Value{jsonValue}, nil
}

func (e *Plugin) arrayAsStrings(values []*fastjson.Value) ([]string, error) {
	var res []string
	for _, v := range values {
		str, err := e.jsonValueAsString(v)
		if err != nil {
			return nil, err
		}
		res = append(res, str)
	}
	return res, nil
}

func (e *Plugin) arrayAsStringsSkipNil(values []*fastjson.Value) []string {
	var res []string
	for _, v := range values {
		str, err := e.jsonValueAsString(v)
		if err == nil {
			res = append(res, str)
		}
	}
	return res
}

func (e *Plugin) arrayAsStringsWithDefault(values []*fastjson.Value, defaultValue string) []string {
	var res []string
	for _, v := range values {
		str, err := e.jsonValueAsString(v)
		if err != nil {
			str = defaultValue
		}
		res = append(res, str)
	}
	return res
}

// note: this returns an error on nil values
// TODO: fix this
func (e *Plugin) readContainerImages(jsonValue *fastjson.Value, indexFilter int) ([]string, error) {
	arr, err := e.getValuesRecursive(jsonValue, indexFilter, "request", "object", "spec", "containers", "image")
	if err != nil {
		return nil, err
	}
	return e.arrayAsStrings(arr)
}

func (e *Plugin) readContainerRepositories(jsonValue *fastjson.Value, indexFilter int) ([]string, error) {
	images, err := e.readContainerImages(jsonValue, indexFilter)
	if err != nil {
		return nil, err
	}
	var repos []string
	for _, image := range images {
		repos = append(repos, strings.Split(strings.Split(image, ":")[0], "@")[0])
	}
	return repos, nil
}

func (e *Plugin) readContainerHostPorts(jsonValue *fastjson.Value, indexFilter int) ([]string, error) {
	containersPorts, err := e.getValuesRecursive(jsonValue, indexFilter, "request", "object", "spec", "containers", "ports")
	if err != nil {
		return nil, err
	}
	var res []string
	for _, ports := range containersPorts {
		if ports == nil {
			continue
		}
		if ports.Type() != fastjson.TypeArray {
			return nil, ErrExtractWrongType
		}
		for _, port := range ports.GetArray() {
			if port.Get("hostPort") != nil {
				p, err := e.jsonValueAsString(port.Get("hostPort"))
				if err != nil {
					return nil, err
				}
				res = append(res, p)
			} else if port.Get("containerPort") != nil {
				// when hostNetwork is true, this will match the host port
				p, err := e.jsonValueAsString(port.Get("containerPort"))
				if err != nil {
					return nil, err
				}
				res = append(res, p)
			}
		}
	}
	return res, nil
}

func (e *Plugin) readFromContainerEffectively(jsonValue *fastjson.Value, indexFilter int, keys ...string) ([]string, error) {
	podID := "0"
	if value := jsonValue.Get(append([]string{"request", "object", "spec"}, keys...)...); value != nil {
		var err error
		podID, err = e.jsonValueAsString(value)
		if err != nil {
			return nil, err
		}
	}
	arr, err := e.getValuesRecursive(jsonValue, indexFilter, append([]string{"request", "object", "spec", "containers"}, keys...)...)
	if err != nil {
		return nil, err
	}
	return e.arrayAsStringsWithDefault(arr, podID), nil
}

func (e *Plugin) extractRulesField(req sdk.ExtractRequest, jsonValue *fastjson.Value, keys ...string) error {
	arr, err := e.getValuesRecursive(jsonValue, e.argIndexFilter(req), append([]string{"request", "object", "rules"}, keys...)...)
	if err != nil {
		return err
	}
	var values []string
	for _, v := range arr {
		if v != nil && v.Type() == fastjson.TypeArray {
			values = append(values, e.arrayAsStringsSkipNil(v.GetArray())...)
		}
	}
	req.SetValue(values)
	return nil
}

func (e *Plugin) extractFromKeys(req sdk.ExtractRequest, jsonValue *fastjson.Value, keys ...string) error {
	jsonValue = jsonValue.Get(keys...)
	if jsonValue == nil {
		return ErrExtractNotAvailable
	}
	if req.IsList() {
		if jsonValue.Type() != fastjson.TypeArray {
			return ErrExtractWrongType
		}
		switch req.FieldType() {
		case sdk.FieldTypeCharBuf:
			var res []string
			for _, v := range jsonValue.GetArray() {
				val, err := e.jsonValueAsString(v)
				if err != nil {
					return err
				}
				res = append(res, val)
			}
			req.SetValue(res)
		default:
			return ErrExtractUnsupportedType
		}
	} else {
		switch req.FieldType() {
		case sdk.FieldTypeCharBuf:
			val, err := e.jsonValueAsString(jsonValue)
			if err != nil {
				return err
			}
			req.SetValue(val)
		default:
			return ErrExtractUnsupportedType
		}
	}
	return nil
}

func (e *Plugin) jsonValueAsString(v *fastjson.Value) (string, error) {
	if v != nil {
		if v.Type() == fastjson.TypeString {
			return string(v.GetStringBytes()), nil
		}
		return string(string(v.MarshalTo(nil))), nil
	}
	return "", ErrExtractWrongType
}
