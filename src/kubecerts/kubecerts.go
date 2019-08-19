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
	"bufio"
	"bytes"
	"crypto/x509"
	"fmt"
	"path/filepath"
	"sslutil"
	"storage"
	"storage/file"
	"strings"
	"text/template"
)

// TODO [low priority] add command line option to get local dns instead of hardcoding cluster.local

type KubeHostsAll map[string]map[string][]string

// generic/nodes -> generic/$node -> certname -> KUBECERT
type AllCerts map[string]map[string]map[string]KubeCert

type KubeTemplateData struct {
	NodeName string
}

type KubeCert struct {
	name                 string
	cert                 *x509.Certificate
	key                  interface{}
	usages               []x509.ExtKeyUsage
	generic              bool
	parent               string
	nodes                []string
	sans                 []string
	commonnameTemplate   string
	organisationTemplate string
	node                 string
}

var (
	certTemplates = []KubeCert{
		{
			name:               "/etc/kubernetes/pki/ca",
			generic:            true,
			commonnameTemplate: "kubernetes",
		},
		{
			name:               "/etc/kubernetes/pki/etcd/ca",
			generic:            true,
			commonnameTemplate: "etcd-ca",
		},
		{
			name:               "/etc/kubernetes/pki/front-proxy-ca",
			generic:            true,
			commonnameTemplate: "front-proxy-ca",
		},
		{
			name:               "/etc/kubernetes/pki/apiserver",
			generic:            false,
			parent:             "/etc/kubernetes/pki/ca",
			nodes:              []string{"masters"},
			commonnameTemplate: "kube-apiserver",
			usages:             []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			sans:               []string{"node", "apisans", "kubernetes", "kubernetes.default", "kubernetes.default.svc", "kubernetes.default.svc.cluster.local", "127.0.0.1", "localhost"},
		},
		{
			name:                 "/etc/kubernetes/pki/apiserver-kubelet-client",
			generic:              false,
			parent:               "/etc/kubernetes/pki/ca",
			nodes:                []string{"masters"},
			commonnameTemplate:   "kube-apiserver-kubelet-client",
			organisationTemplate: "system:masters",
			usages:               []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		},
		{
			name:                 "/etc/kubernetes/pki/admin",
			generic:              true,
			parent:               "/etc/kubernetes/pki/ca",
			commonnameTemplate:   "kubernetes-admin",
			organisationTemplate: "system:masters",
			usages:               []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		},
		{
			name:               "/etc/kubernetes/pki/controller-manager",
			generic:            false,
			parent:             "/etc/kubernetes/pki/ca",
			nodes:              []string{"masters"},
			commonnameTemplate: "system:kube-controller-manager",
			usages:             []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		},
		{
			name:                 "/etc/kubernetes/pki/kubelet",
			generic:              false,
			parent:               "/etc/kubernetes/pki/ca",
			nodes:                []string{"masters", "workers"},
			commonnameTemplate:   "system:node:{{.NodeName}}",
			organisationTemplate: "system:nodes",
			usages:               []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		},
		{
			name:                 "/var/lib/kubelet/pki/kubelet",
			generic:              false,
			parent:               "/etc/kubernetes/pki/ca",
			nodes:                []string{"masters", "workers"},
			commonnameTemplate:   "{{.NodeName}}",
			organisationTemplate: "system:nodes",
			usages:               []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			sans:                 []string{"node"},
		},
		{
			name:                 "/var/lib/kube-proxy/pki/kubelet",
			generic:              false,
			parent:               "/etc/kubernetes/pki/ca",
			nodes:                []string{"masters", "workers"},
			commonnameTemplate:   "{{.NodeName}}",
			organisationTemplate: "system:nodes",
			usages:               []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			sans:                 []string{"node"},
		},
		{
			name:               "/etc/kubernetes/pki/scheduler",
			generic:            false,
			parent:             "/etc/kubernetes/pki/ca",
			nodes:              []string{"masters"},
			commonnameTemplate: "system:kube-scheduler",
			usages:             []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		},
		{
			name:                 "/etc/kubernetes/pki/kube-proxy",
			generic:              false,
			parent:               "/etc/kubernetes/pki/ca",
			nodes:                []string{"masters", "workers"},
			commonnameTemplate:   "system:kube-proxy",
			organisationTemplate: "system:node-proxier",
			usages:               []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		},
		{
			name:               "/etc/kubernetes/pki/front-proxy-client",
			generic:            false,
			parent:             "/etc/kubernetes/pki/front-proxy-ca",
			nodes:              []string{"masters", "workers"},
			commonnameTemplate: "front-proxy-client",
			usages:             []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		},
		{
			name:               "/etc/kubernetes/pki/etcd/server",
			cert:               nil,
			key:                nil,
			generic:            false,
			parent:             "/etc/kubernetes/pki/etcd/ca",
			nodes:              []string{"etcd"},
			commonnameTemplate: "{{.NodeName}}",
			usages:             []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			sans:               []string{"node", "127.0.0.1", "localhost"},
		},
		{
			name:               "/etc/kubernetes/pki/etcd/peer",
			generic:            false,
			parent:             "/etc/kubernetes/pki/etcd/ca",
			nodes:              []string{"etcd"},
			commonnameTemplate: "{{.NodeName}}",
			usages:             []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
			sans:               []string{"node", "127.0.0.1", "localhost"},
		},
		{
			name:                 "/etc/kubernetes/pki/etcd/etcd-healthcheck-client",
			generic:              false,
			parent:               "/etc/kubernetes/pki/etcd/ca",
			nodes:                []string{"masters"},
			commonnameTemplate:   "kube-etcd-healthcheck-client",
			organisationTemplate: "system:masters",
			usages:               []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		},
		{
			name:                 "/etc/kubernetes/pki/apiserver-etcd-client",
			generic:              false,
			parent:               "/etc/kubernetes/pki/etcd/ca",
			nodes:                []string{"masters"},
			commonnameTemplate:   "kube-apiserver-etcd-client",
			organisationTemplate: "system:masters",
			usages:               []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		},
	}
)

func renderTemplate(templateString string, data KubeTemplateData) string {
	var outBuf bytes.Buffer
	outBufWriter := bufio.NewWriter(&outBuf)
	tmpl, err := template.New("template").Parse(templateString)
	if err != nil {
		fmt.Printf("error parsing template: %q", err)
		return templateString
	}
	err = tmpl.Execute(outBufWriter, data)
	if err != nil {
		fmt.Printf("error executing template: %q", err)
		return templateString
	}
	outBufWriter.Flush()
	return outBuf.String()
}

func DoCertGen(cert string, hosts KubeHostsAll, certs *AllCerts) (err error) {

	all := make(AllCerts)
	all["nodes"] = make(map[string]map[string]KubeCert)
	all["generic"] = make(map[string]map[string]KubeCert)
	all["generic"]["generic"] = make(map[string]KubeCert)

	for _, values := range certTemplates {
		if values.generic {
			fmt.Printf("%s -> %t\n", values.name, values.generic)
			certConf := sslutil.NewCertConfig(365, values.commonnameTemplate, []string{values.organisationTemplate}, nil)
			kc := values
			if values.parent == "" {
				kc.cert, kc.key, err = sslutil.NewSelfSignedCACert(*certConf, nil)
			} else {
				kc.cert, kc.key, err = sslutil.GenerateSelfSignedCertKey(*certConf, all["generic"]["generic"][values.parent].cert, all["generic"]["generic"][values.parent].key, nil)
			}
			all["generic"]["generic"][values.name] = kc
		}
	}
	for hosttype, nodes := range hosts {

		if hosttype == "apisans" {
			continue
		}
		fmt.Printf("%s\n", hosttype)
		for node, altnames := range nodes {
			if all["nodes"][node] == nil {
				all["nodes"][node] = make(map[string]KubeCert)
			}
			fmt.Printf("\t%s -> %q\n", node, altnames)
			for _, values := range certTemplates {
				if !values.generic {
					for _, nodetype := range values.nodes {
						if nodetype == hosttype {
							fmt.Printf("\t\t\t%s -> %q\n", values.name, values.nodes)
							sans := make([]string, 0)
							for _, santype := range values.sans {
								switch santype {
								case "node":
									sans = append(sans, node)
									sans = append(sans, altnames...)
								case "apisans":
									for apihost, apialtnames := range hosts["apisans"] {
										sans = append(sans, apihost)
										sans = append(sans, apialtnames...)
									}
								}
							}

							commonName := renderTemplate(values.commonnameTemplate, KubeTemplateData{node})
							organisation := renderTemplate(values.organisationTemplate, KubeTemplateData{node})
							kc := values
							if values.parent == "" {
								certConf := sslutil.NewCertConfig(365, commonName, []string{organisation}, nil)
								kc.cert, kc.key, err = sslutil.NewSelfSignedCACert(*certConf, nil)
							} else {
								certConf := sslutil.NewCertConfig(365, commonName, []string{organisation}, sans)
								kc.cert, kc.key, err = sslutil.GenerateSelfSignedCertKey(*certConf, all["generic"]["generic"][values.parent].cert, all["generic"]["generic"][values.parent].key, nil)
							}
							all["nodes"][node][values.name] = kc
						}
					}
				}
			}
		}
	}

	for outtype, outnodes := range all {
		for node, certs := range outnodes {
			for path, kc := range certs {

				storeFile := file.NewDefaultsStoreFile()
				var s storage.StoreDrv = storeFile

				certdir := filepath.Dir(path)
				if outtype == "generic" {
					certdir = filepath.Join("outputs/system", "generic", certdir)
				} else {
					certdir = filepath.Join("outputs/system", outtype, node, certdir)
				}
				storeFile.Basepath = certdir
				storeFile.Filename = filepath.Base(path)

				storeFile.Extension = ".crt"
				certpem := sslutil.EncodeCertPEM(kc.cert)
				_ = s.Write(certpem)

				storeFile.Extension = ".key"
				keypem, _ := sslutil.MarshalPrivateKeyToPEM(kc.key)
				_ = s.Write(keypem)
			}
		}
	}
	return nil
}

func Execute(apiSans *string, masters *string, workers *string) error {
	kh, err := get_kubehosts(apiSans, masters, workers)
	if err != nil {
		return err
	}
	_ = DoCertGen("x", *kh, nil)
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

func get_kubehosts(apisans *string, masters *string, workers *string) (cluster *KubeHostsAll, err error) {

	var kh = KubeHostsAll{
		"apisans": map[string][]string{},
		"masters": map[string][]string{},
		"workers": map[string][]string{},
		"etcd":    map[string][]string{},
	}

	api, err := parsesans(apisans, false)
	if err != nil {
		return nil, err
	}
	kh["apisans"] = api
	mst, err := parsesans(masters, false)
	if err != nil {
		return nil, err
	}
	kh["masters"] = mst
	kh["etcd"] = mst

	wrk, err := parsesans(workers, false)
	if err != nil {
		return nil, err
	}
	kh["workers"] = wrk

	//kubehosts := KubeHosts{
	//	apisans: api,
	//	masters: mst,
	//	workers: wrk,
	//}

	return &kh, err
}
