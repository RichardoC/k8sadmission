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
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins/source"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
	"github.com/valyala/fastjson"
)

const (
	webServerShutdownTimeoutSecs = 5
	webServerEventChanBufSize    = 50
)

// TODO: have refresh logic as documented in https://github.com/falcosecurity/plugins/issues/191
func (k *Plugin) Open(params string) (source.Instance, error) {
	u, err := url.Parse(params)
	if err != nil {
		return nil, err
	}

	switch u.Scheme {
	case "http":
		return nil, errors.New("only HTTPS supported for admission . Use https, or read from a file")
	// 	return k.OpenWebServer(u.Host, u.Path, false)
	case "https":
		return k.OpenWebServer(u.Host, u.Path, true)
	case "": // by default, fallback to opening a filepath
		trimmed := strings.TrimSpace(params)

		fileInfo, err := os.Stat(trimmed)
		if err != nil {
			return nil, err
		}
		if !fileInfo.IsDir() {
			file, err := os.Open(trimmed)
			if err != nil {
				return nil, err
			}
			return k.OpenReader(file)
		}

		files, err := ioutil.ReadDir(trimmed)
		if err != nil {
			return nil, err
		}

		sort.Slice(files, func(i, j int) bool {
			return files[i].ModTime().Before(files[j].ModTime())
		})

		// open all files as reader
		results := []io.Reader{}
		for _, f := range files {
			if !f.IsDir() {
				auditFile, err := os.Open(trimmed + "/" + f.Name())
				if err != nil {
					return nil, err
				}
				results = append(results, auditFile)
				results = append(results, strings.NewReader("\n"))
			}
		}

		// concat the readers and wrap with a no-op Close method
		AllAuditFiles := io.NopCloser(io.MultiReader(results...))
		return k.OpenReader(AllAuditFiles)
	}

	return nil, fmt.Errorf(`scheme "%s" is not supported`, u.Scheme)
}

// OpenReader opens a source.Instance event stream that reads K8S Audit
// Events from a io.ReadCloser. Each Event is a JSON object encoded with
// JSONL notation (see: https://jsonlines.org/).
func (k *Plugin) OpenReader(r io.ReadCloser) (source.Instance, error) {
	evtC := make(chan source.PushEvent)

	go func() {
		defer close(evtC)
		var parser fastjson.Parser
		scanner := bufio.NewScanner(r)
		scanner.Split(bufio.ScanLines)
		buf := make([]byte, 0, 64*1024)
		scanner.Buffer(buf, 4*1024*1024) // enable lines to be up to 4MB
		for scanner.Scan() {
			line := scanner.Text()
			if len(line) > 0 {
				k.parseAuditEventsAndPush(&parser, ([]byte)(line), evtC)
			}
		}
		err := scanner.Err()
		if err != nil {
			evtC <- source.PushEvent{Err: err}
		}
	}()

	return source.NewPushInstance(
		evtC,
		source.WithInstanceClose(func() { r.Close() }),
		source.WithInstanceEventSize(uint32(k.Config.MaxEventSize)))
}

// minimum viable response
// https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/#response
const responseTemplate = `{
	"apiVersion": "admission.k8s.io/v1",
	"kind": "AdmissionReview",
	"response": {
		"uid": "%s",
		"allowed": true
	}
}`

func addTimestamp(requestBody []byte) ([]byte, error) {
	currentTime := time.Now().Format(time.RFC3339Nano)
	return sjson.SetBytes(requestBody, "requestReceivedTimestamp", currentTime)
}

// OpenWebServer opens a source.Instance event stream that receives K8S Audit
// Events by starting a server and listening for JSON webhooks. The expected
// JSON format is the one of K8S API Server webhook backend
// (see: https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/#webhook-backend).
func (k *Plugin) OpenWebServer(address, endpoint string, ssl bool) (source.Instance, error) {
	ctx, cancelCtx := context.WithCancel(context.Background())
	serverEvtChan := make(chan []byte, webServerEventChanBufSize)
	evtChan := make(chan source.PushEvent)

	// launch webserver gorountine. This listens for webhooks coming from
	// the k8s api server and sends every valid payload to serverEvtChan so
	// that an HTTP response can be sent as soon as possible. Each payload is
	// then parsed to extract the list of audit events contained by the
	// event-parser goroutine
	m := http.NewServeMux()
	s := &http.Server{Addr: address, Handler: m}
	sendBody := func(b []byte) {
		defer func() {
			if r := recover(); r != nil {
				k.logger.Println("request dropped while shutting down server ")
			}
		}()
		serverEvtChan <- b
	}
	m.HandleFunc(endpoint, func(w http.ResponseWriter, req *http.Request) {
		if req.Method != "POST" {
			http.Error(w, fmt.Sprintf("%s method not allowed", req.Method), http.StatusMethodNotAllowed)
			return
		}
		if !strings.Contains(req.Header.Get("Content-Type"), "application/json") {
			http.Error(w, "wrong Content Type", http.StatusBadRequest)
			return
		}
		req.Body = http.MaxBytesReader(w, req.Body, int64(k.Config.WebhookMaxBatchSize))
		bytes, err := ioutil.ReadAll(req.Body)
		if err != nil {
			msg := fmt.Sprintf("bad request: %s", err.Error())
			k.logger.Println(msg)
			http.Error(w, msg, http.StatusBadRequest)
			return
		}
		if !gjson.ValidBytes(bytes) {
			// k.logger.Debugw("invalid json", "body", bytes)
			w.Header().Set("error", "invalid json")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		requestUid := gjson.GetBytes(bytes, "request.uid").Str
		if requestUid == "" {
			// k.logger.Debugln("failed to find request uid")
			w.Header().Set("error", "uid not provided")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
		// Template the uid into our default approval and finish up
		fmt.Fprintf(w, responseTemplate, requestUid)
		bytes, err = addTimestamp(bytes)
		if err != nil {
			msg := fmt.Sprintf("failed to add requestReceivedTimestamp: %s", err.Error())
			k.logger.Println(msg)
			return
		}
		// if this all passed, send the body to be processed
		sendBody(bytes)
	})
	go func() {
		defer close(serverEvtChan)
		var err error
		if ssl {
			err = s.ListenAndServeTLS(k.Config.TLSCert, k.Config.TLSKey)
		}
		if err != nil && err != http.ErrServerClosed {
			evtChan <- source.PushEvent{Err: err}
		}
	}()

	// launch event-parser gorountine. This received webhook payloads
	// and parses their content to extract the list of audit events contained.
	// Then, events are sent to the Push-mode event source instance channel.
	go func() {
		defer close(evtChan)
		var parser fastjson.Parser
		for {
			select {
			case bytes, ok := <-serverEvtChan:
				if !ok {
					return
				}
				k.parseAuditEventsAndPush(&parser, bytes, evtChan)
			case <-ctx.Done():
				return
			}
		}
	}()

	// open new instance in with "push" prebuilt
	return source.NewPushInstance(
		evtChan,
		source.WithInstanceContext(ctx),
		source.WithInstanceClose(func() {
			// on close, attempt shutting down the webserver gracefully
			timedCtx, cancelTimeoutCtx := context.WithTimeout(ctx, time.Second*webServerShutdownTimeoutSecs)
			defer cancelTimeoutCtx()
			s.Shutdown(timedCtx)
			cancelCtx()
		}),
		source.WithInstanceEventSize(uint32(k.Config.MaxEventSize)),
	)
}

// todo: optimize this to cache by event number
func (k *Plugin) String(evt sdk.EventReader) (string, error) {
	evtBytes, err := ioutil.ReadAll(evt.Reader())
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%v", string(evtBytes)), nil
}

// here we make all errors non-blocking for single events by
// simply logging them, to ensure consumers don't close the
// event source with bad or malicious payloads
func (k *Plugin) parseAuditEventsAndPush(parser *fastjson.Parser, payload []byte, c chan<- source.PushEvent) {
	data, err := parser.ParseBytes(payload)
	if err != nil {
		k.logger.Println(err.Error())
		return
	}
	values, err := k.ParseAuditEventsJSON(data)
	if err != nil {
		k.logger.Println(err.Error())
		return
	}
	for _, v := range values {
		if v.Err != nil {
			k.logger.Println(v.Err.Error())
			continue
		} else {
			c <- *v
		}
	}
}

// ParseAuditEventsPayload parses a byte slice representing a JSON payload
// that contains one or more K8S Audit Events. If the payload is parsed
// correctly, returns the slice containing all the events parsed and a nil error.
// A nil slice and a non-nil error is returned in case the parsing fails.
//
// Even if a nil error is returned, each of the events of the returned slice can
// still contain an error (source.PushEvent.Err is non-nil). The reason is that
// if a single event is corrupted, this function still attempts to parse the
// rest of the events in the payload.
func (k *Plugin) ParseAuditEventsPayload(payload []byte) ([]*source.PushEvent, error) {
	value, err := fastjson.ParseBytes(payload)
	if err != nil {
		return nil, err
	}
	return k.ParseAuditEventsJSON(value)
}

// ParseAuditEventsJSON is the same as ParseAuditEventsPayload, but takes
// a pre-parsed JSON as input. The JSON representation is the one of the
// fastjson library.
func (k *Plugin) ParseAuditEventsJSON(value *fastjson.Value) ([]*source.PushEvent, error) {
	if value == nil {
		return nil, fmt.Errorf("can't parse nil JSON message")
	}
	return []*source.PushEvent{k.parseSingleAuditEventJSON(value)}, nil
}

func (k *Plugin) parseSingleAuditEventJSON(value *fastjson.Value) *source.PushEvent {
	res := &source.PushEvent{}
	// TODO, fix all this

	operation := value.GetStringBytes("request", "operation")
	// we failed to find the operation
	if operation == nil {
		res.Err = fmt.Errorf("failed to find operation from event: %+v", value)
		return res
	}

	timestamp, err := time.Parse(time.RFC3339Nano, string(value.GetStringBytes("requestReceivedTimestamp")))
	if err != nil {
		res.Err = fmt.Errorf("failed to get timestamp from object %+v err :%+v", value, err)
		return res
	}
	// Required as otherwise we lose the data
	res.Data = value.MarshalTo(nil)

	res.Timestamp = timestamp
	return res
}
