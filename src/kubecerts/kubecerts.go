/*
 * Copyright (c) 2019. Stefan Kiss.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package kubecerts

import (
	"fmt"
	"strings"
)

type KubeHosts struct {
	apisans map[string][]string
	masters map[string][]string
	workers map[string][]string
}

func Execute(apisans *string, masters *string, workers *string) error {
	kh, err := get_kubehosts(apisans, masters, workers)
	if kh == nil {
		fmt.Printf("%q", err)
		return nil
	}
	fmt.Printf("%q", *kh)
	return nil
}

func parsesans(hosts *string, single bool) (map[string][]string, error) {
	if hosts == nil || *hosts == "" {
		return nil, fmt.Errorf("must have at least one host")
	}

	hostslist := strings.Split(*hosts, ",")
	if single && len(hostslist) > 1 {
		return nil, fmt.Errorf("only one main api host allowed")
	}
	var hostmap = make(map[string][]string)

	for _, host := range hostslist {

		extrasans := strings.Split(host, "/")
		if len(extrasans) > 2 {
			return nil, fmt.Errorf("only node name per host allowed")
		}
		node := extrasans[0]
		if len(extrasans) > 1 {
			hostmap[node] = strings.Split(extrasans[1], ":")
			for _, extrasan := range hostmap[node] {
				if extrasan == "" {
					return nil, fmt.Errorf("any extrasan supplied must not be empty for %q", node)
				}
			}
		} else {
			hostmap[node] = nil
		}
	}
	return hostmap, nil
}

func get_kubehosts(apisans *string, masters *string, workers *string) (cluster *KubeHosts, err error) {

	api, err := parsesans(apisans, false)
	if err != nil {
		return nil, err
	}

	mst, err := parsesans(masters, false)
	if err != nil {
		return nil, err
	}

	wrk, err := parsesans(workers, false)
	if err != nil {
		return nil, err
	}

	kh := KubeHosts{
		apisans: api,
		masters: mst,
		workers: wrk,
	}

	return &kh, err
}
