// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2023 The Falco Authors.

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

package outputs

import (
	"log"
	"sort"
	"strconv"
	"time"

	"github.com/falcosecurity/falcosidekick/types"
)

type splunkPayload struct {
	Category   string                 `json:"category,omitempty"`
	EventType  string                 `json:"eventType,omitempty"`
	Timestamp  int64                  `json:"timestamp,omitempty"`
	Dimensions map[string]interface{} `json:"dimensions,omitempty"`
	Properties map[string]interface{} `json:"properties,omitempty"`
}

const SplunkContentType = "application/json"

func newSplunkPayload(falcopayload types.FalcoPayload) []splunkPayload {
	var d splunkPayload

	properties := make(map[string]interface{})
	for _, item := range getSortedStringKeys(falcopayload.OutputFields) {
		//Some properties need to be dimensions
		if item != "container.id" &&
			item != "container.image.repository" &&
			item != "container.image.tag" &&
			item != "container.name" &&
			item != "k8sclustername" &&
			item != "k8s.ns.name" &&
			item != "k8s.pod.name" {
			properties[item] = falcopayload.OutputFields[item]
		}

	}
	// Looks like Splunk API returns HTTP 200 when strings are too long
	/* for key, value := range properties {
		if str, ok := value.(string); ok {
			if len(str) > 240 {
				truncatedStr := str[:240]
				properties[key] = truncatedStr
			}
		}
	} */
	if len(falcopayload.Tags) != 0 {
		sort.Strings(falcopayload.Tags)
		//properties = append(properties, falcopayload.Tags...)
		for i := range falcopayload.Tags {
			istr := strconv.Itoa(i)
			properties["tag-"+istr] = falcopayload.Tags[i]

		}

	}
	properties["uuid"] = falcopayload.UUID
	// Looks like Splunk API returns HTTP 200 when strings are too long
	properties["output"] = falcopayload.Output[:240]
	d.Properties = properties

	dimensions := make(map[string]interface{})
	//hostname: the name of the host running Falco (can be the hostname inside the container). Would be usefull outside K8s. Within K8s it's kind of pointless and confusing
	/* if falcopayload.Hostname != "" {
		dimensions["host.name"] = falcopayload.Hostname
	} */
	dimensions["priority"] = falcopayload.Priority.String()
	dimensions["rule"] = falcopayload.Rule
	dimensions["source"] = falcopayload.Source
	if _, ok := falcopayload.OutputFields["container.id"]; ok {
		dimensions["container.id"] = falcopayload.OutputFields["container.id"]
	}
	log.Println("t0t0")
	if _, ok := falcopayload.OutputFields["container.image.repository"]; ok {
		log.Println("t0t0")
		log.Println(falcopayload.OutputFields["container.image.repository"])
		dimensions["container.image.repository"] = falcopayload.OutputFields["container.image.repository"]
	}
	if _, ok := falcopayload.OutputFields["container.image.tag"]; ok {
		dimensions["container.image.tag"] = falcopayload.OutputFields["container.image.tag"]
	}
	if _, ok := falcopayload.OutputFields["container.name"]; ok {
		dimensions["container.name"] = falcopayload.OutputFields["container.name"]
	}
	if _, ok := falcopayload.OutputFields["k8s.ns.name"]; ok {
		dimensions["k8s.namespace.name"] = falcopayload.OutputFields["k8s.ns.name"]
	}
	if _, ok := falcopayload.OutputFields["k8s.pod.name"]; ok {
		dimensions["k8s.pod.name"] = falcopayload.OutputFields["k8s.pod.name"]
	}
	if _, ok := falcopayload.OutputFields["k8sclustername"]; ok {
		dimensions["k8s.cluster.name"] = falcopayload.OutputFields["k8sclustername"]
	}
	if _, ok := falcopayload.OutputFields["k8sclustername"]; ok {
		dimensions["k8s.cluster.name"] = falcopayload.OutputFields["k8sclustername"]
	}

	d.Dimensions = dimensions

	d.Category = "USER_DEFINED"
	d.EventType = "falco"

	currentTime := falcopayload.Time.UnixNano() / int64(time.Millisecond)
	//Debug
	//currentTime = time.Now().UnixNano() / int64(time.Millisecond)
	d.Timestamp = currentTime

	return []splunkPayload{d}
}

// SplunkPost posts event to Splunk Observability
func (c *Client) SplunkPost(falcopayload types.FalcoPayload) {
	c.Stats.Splunk.Add(Total, 1)

	c.ContentType = SplunkContentType

	c.httpClientLock.Lock()
	defer c.httpClientLock.Unlock()
	c.AddHeader("X-SF-Token", c.Config.Splunk.IngestToken)
	err := c.Post(newSplunkPayload(falcopayload))
	if err != nil {
		go c.CountMetric(Outputs, 1, []string{"output:splunk", "status:error"})
		c.Stats.Splunk.Add(Error, 1)
		c.PromStats.Outputs.With(map[string]string{"destination": "Splunk", "status": Error}).Inc()
		log.Printf("[ERROR] : Splunk - %v\n", err)
		return
	}

	go c.CountMetric(Outputs, 1, []string{"output:splunk", "status:ok"})
	c.Stats.Splunk.Add(OK, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "splunk", "status": OK}).Inc()
}
