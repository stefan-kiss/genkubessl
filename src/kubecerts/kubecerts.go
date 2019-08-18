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
	"sslutil"
	"strings"
)

type KubeHosts struct {
	apisans map[string][]string
	masters map[string][]string
	workers map[string][]string
}

func Execute(apisans *string, masters *string, workers *string) error {
	kh, err := get_kubehosts(apisans, masters, workers)
	if err != nil {
		return err
	}

	for k, v := range kh.apisans {
		kh.apisans[k] = append(v, "kubernetes", "kubernetes.default", "kubernetes.default.svc")
	}

	caconfig := sslutil.NewCAConfig(30, "kubernetes-ca", []string{"kubernetes"}, nil)
	cacert, cakey, err := sslutil.NewSelfSignedCACert(*caconfig, nil)
	capem := sslutil.EncodeCertPEM(cacert)
	cakeypem, _ := sslutil.MarshalPrivateKeyToPEM(cakey)
	fmt.Printf("capem\n%s\n", capem)
	fmt.Printf("cakeypem\n%s\n", cakeypem)

	for k, v := range kh.apisans {
		certconfig := sslutil.NewCAConfig(30, k, nil, v)
		cert, key, _ := sslutil.GenerateSelfSignedCertKey(*certconfig, cacert, cakey, nil)

		certpem := sslutil.EncodeCertPEM(cert)
		certkeypem, _ := sslutil.MarshalPrivateKeyToPEM(key)
		fmt.Printf("certpem\n%s\n", certpem)
		fmt.Printf("certkeypem\n%s\n", certkeypem)

	}

	for k, v := range kh.masters {
		certconfig := sslutil.NewCAConfig(30, k, nil, v)
		cert, key, _ := sslutil.GenerateSelfSignedCertKey(*certconfig, cacert, cakey, nil)

		certpem := sslutil.EncodeCertPEM(cert)
		certkeypem, _ := sslutil.MarshalPrivateKeyToPEM(key)
		fmt.Printf("certpem\n%s\n", certpem)
		fmt.Printf("certkeypem\n%s\n", certkeypem)

	}

	for k, v := range kh.workers {
		certconfig := sslutil.NewCAConfig(30, k, nil, v)
		cert, key, _ := sslutil.GenerateSelfSignedCertKey(*certconfig, cacert, cakey, nil)

		certpem := sslutil.EncodeCertPEM(cert)
		certkeypem, _ := sslutil.MarshalPrivateKeyToPEM(key)
		fmt.Printf("certpem\n%s\n", certpem)
		fmt.Printf("certkeypem\n%s\n", certkeypem)

	}

	fmt.Printf("%q", *kh)
	return nil
}

//func GenKubeCrt(cacert *x509.Certificate,cakey interface{},host string,sans []string) (cert *x509.Certificate,key interface{},err error) {
//	sslutil.GenerateSelfSignedCertKey
//}

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
