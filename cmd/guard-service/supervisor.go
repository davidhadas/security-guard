/*
Copyright 2022 The Knative Authors

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

package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"sync"
	"time"

	spec "knative.dev/security-guard/pkg/apis/guard/v1alpha1"
	pi "knative.dev/security-guard/pkg/pluginterfaces"
)

const supervisorMaxDelayTime = 5 * time.Second // 5sec

// Interface with a supervisor
type supervisor struct {
	mutex              *sync.Mutex                    // protect access to alertReports map
	serviceReportMap   map[string]spec.ServiceReports // Queue alerts for delivery to Supervisor
	numQueuedAlerts    uint32                         // num Alerts queued
	supervisorUrl      string
	httpClient         http.Client
	lastSupervisorSync time.Time
}

type supervisorSync struct {
	Services []spec.ServiceReports `json:"services"`
}

func NewSupervisor() *supervisor {
	supervisorUrl, err := os.ReadFile("/supervisor/url")
	if err != nil {
		pi.Log.Infof("Supervisor not defined")
		return nil
	}

	supervisorSan, err := os.ReadFile("/supervisor/san")
	if err != nil {
		pi.Log.Infof("Supervisor not defined")
		return nil
	}
	certPool, err := x509.SystemCertPool()
	if err != nil {
		certPool = x509.NewCertPool()
	}
	rootCA, err := os.ReadFile("/supervisor/ca.crt")
	if err != nil {
		pi.Log.Infof("Supervisor ROOT_CA is missing")
		return nil
	}

	if ok := certPool.AppendCertsFromPEM(rootCA); !ok {
		pi.Log.Infof("Supervisor failed to AppendCertsFromPEM from ROOT_CA")
		return nil
	}

	certificate, err := tls.LoadX509KeyPair("/supervisor/tls.crt", "/supervisor/tls.key")
	if err != nil {
		pi.Log.Infof("Supervisor could not load certificate")
		return nil
	}
	pi.Log.Infof("Supervisor config ok")

	s := &supervisor{}
	s.serviceReportMap = make(map[string]spec.ServiceReports, 4)
	s.mutex = &sync.Mutex{}
	s.supervisorUrl = string(supervisorUrl)
	s.httpClient.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: false,
			ServerName:         string(supervisorSan),
			RootCAs:            certPool,
			Certificates:       []tls.Certificate{certificate},
		},
	}
	return s
}

func (s *supervisor) tick() {
	if s.numQueuedAlerts == 0 {
		return
	}
	if time.Since(s.lastSupervisorSync) < supervisorMaxDelayTime && s.numQueuedAlerts < 10 {
		return
	}
	s.lastSupervisorSync = time.Now()

	s.mutex.Lock()
	alertReports := s.serviceReportMap
	s.serviceReportMap = make(map[string]spec.ServiceReports, 4)
	s.numQueuedAlerts = 0
	defer s.mutex.Unlock()

	sync := supervisorSync{
		Services: make([]spec.ServiceReports, s.numQueuedAlerts),
	}
	i := 0
	for _, report := range alertReports {
		sync.Services[i] = report
	}
	go s.updateSupervisor(sync)
}

func (s *supervisor) updateSupervisor(sync supervisorSync) {

	buf, err := json.Marshal(sync)
	if err != nil {
		pi.Log.Infof("Supervisor failed to Marshal Supervisor reports: %v", err)
		return
	}

	reqBody := bytes.NewBuffer(buf)
	req, err := http.NewRequest(http.MethodPost, s.supervisorUrl+"/sync", reqBody)
	if err != nil {
		pi.Log.Infof("Supervisor failed to create Http.NewRequest error %v", err)
		return
	}
	pi.Log.Debugf("Sync with Supervisor!")

	res, postErr := s.httpClient.Do(req)
	if postErr != nil {
		pi.Log.Infof("Supervisor httpClient.Do error %v", postErr)
		return
	}
	if res.StatusCode != http.StatusOK {
		pi.Log.Infof("Supervisor did not respond with 200 OK")
		return
	}

	// TBD what is needed here depending on possible responses from Supervisor
	if res.Body != nil {
		body, readErr := io.ReadAll(res.Body)
		if readErr != nil {
			pi.Log.Infof("Supervisor response error %v", readErr)
			return
		}
		if len(body) != 0 {
			pi.Log.Debugf("Supervisor response: %s", string(body))
		}
		res.Body.Close()
	}
}

func (s *supervisor) addAlerts(ns, sid, podname string, alerts []spec.AlertReport) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	service := podname + "." + sid + "." + ns
	reports, ok := s.serviceReportMap[service]
	if !ok {
		var reports spec.ServiceReports

		reports.PodName = podname
		reports.Namespace = ns
		reports.ServiceId = sid
		reports.Alerts = alerts
		s.serviceReportMap[service] = reports
	} else {
		reports.Alerts = append(reports.Alerts, alerts...)
	}

	for _, report := range alerts {
		time := time.Unix(report.Time, 0)
		pi.Log.Debugf("---- %d alerts since %02d:%02d:%02d %s -> %v", report.Count, time.Hour(), time.Minute(), time.Second(), report.Level, report.Alert)
	}
}
