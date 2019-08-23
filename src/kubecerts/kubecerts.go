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
	"k8s.io/client-go/util/keyutil"
	"log"
	"path/filepath"
	"sslutil"
	"storage"
	"strings"
	"text/template"
	"time"
)

// TODO [low priority] add command line option to get local dns instead of hardcoding cluster.local

type KubeHostsAll map[string]map[string][]string

type KubeTemplateData struct {
	NodeName string
}

type KubeCertTemplate struct {
	path                 string
	usages               []x509.ExtKeyUsage
	parent               string
	nodes                []string
	nodeSans             bool
	apiSans              bool
	extraSans            []string
	commonnameTemplate   string
	organisationTemplate string
}

type KubeCert struct {
	cert         *x509.Certificate
	certPEM      []byte
	key          interface{}
	keyPEM       []byte
	node         string
	commonName   string
	organisation []string
	sans         []string
	templateIdx  int
	readStorage  storage.StoreDrv
	writeStorage storage.StoreDrv
	failed       string
}

var (
	KubeCAMap    = make(map[string]int)
	AllKubeCerts = make([]*KubeCert, 0)

	defaultNodeSans = []string{"127.0.0.1", "localhost", "::1"}

	// Behavior for dealing with existing certificates. currently hardcoded.
	// regenerate all
	ForceRegen = false
	// overwrite if fails checks
	OverWrite = true

	// storage related // hardcoded for now
	StorageReadType  = "file"
	StorageWriteType = "file"

	StorageReadLocation  = "outputs/system"
	StorageWriteLocation = "outputs/system"

	GlobalPath = "global"
	NodesPath  = "nodes"

	// hardcoded min duration
	CheckCertMinValid = time.Hour * 24 * 10

	// Certificate authorities should always be first in order to be processed first.
	kubeCertTemplates = []KubeCertTemplate{
		{
			path:               "/etc/kubernetes/pki/ca",
			commonnameTemplate: "kubernetes",
		},
		{
			path:               "/etc/kubernetes/pki/etcd/ca",
			commonnameTemplate: "etcd-ca",
		},
		{
			path:               "/etc/kubernetes/pki/front-proxy-ca",
			commonnameTemplate: "front-proxy-ca",
		},
		{
			path:               "/etc/kubernetes/pki/apiserver",
			parent:             "/etc/kubernetes/pki/ca",
			nodes:              []string{"masters"},
			commonnameTemplate: "kube-apiserver",
			usages:             []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			nodeSans:           true,
			apiSans:            true,
			extraSans:          []string{"kubernetes", "kubernetes.default", "kubernetes.default.svc", "kubernetes.default.svc.cluster.local"},
		},
		{
			path:                 "/etc/kubernetes/pki/apiserver-kubelet-client",
			parent:               "/etc/kubernetes/pki/ca",
			nodes:                []string{"masters"},
			commonnameTemplate:   "kube-apiserver-kubelet-client",
			organisationTemplate: "system:masters",
			usages:               []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		},
		{
			path:                 "/etc/kubernetes/pki/admin",
			parent:               "/etc/kubernetes/pki/ca",
			commonnameTemplate:   "kubernetes-admin",
			organisationTemplate: "system:masters",
			usages:               []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		},
		{
			path:               "/etc/kubernetes/pki/controller-manager",
			parent:             "/etc/kubernetes/pki/ca",
			nodes:              []string{"masters"},
			commonnameTemplate: "system:kube-controller-manager",
			usages:             []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		},
		{
			path:                 "/etc/kubernetes/pki/kubelet",
			parent:               "/etc/kubernetes/pki/ca",
			nodes:                []string{"masters", "workers"},
			commonnameTemplate:   "system:node:{{.NodeName}}",
			organisationTemplate: "system:nodes",
			usages:               []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		},
		{
			path:                 "/var/lib/kubelet/pki/kubelet",
			parent:               "/etc/kubernetes/pki/ca",
			nodes:                []string{"masters", "workers"},
			commonnameTemplate:   "{{.NodeName}}",
			organisationTemplate: "system:nodes",
			usages:               []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			nodeSans:             true,
		},
		// TODO determine if we need kube proxy server cert
		// kubeadm just uses a serviceaccount token
		//{
		//	path:                 "/var/lib/kube-proxy/pki/kube-proxy",
		//	parent:               "/etc/kubernetes/pki/ca",
		//	nodes:                []string{"masters", "workers"},
		//	commonnameTemplate:   "{{.NodeName}}",
		//	organisationTemplate: "system:nodes",
		//	usages:               []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		//	nodeSans:           true,
		//},
		{
			path:               "/etc/kubernetes/pki/scheduler",
			parent:             "/etc/kubernetes/pki/ca",
			nodes:              []string{"masters"},
			commonnameTemplate: "system:kube-scheduler",
			usages:             []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		},
		{
			path:                 "/etc/kubernetes/pki/kube-proxy",
			parent:               "/etc/kubernetes/pki/ca",
			nodes:                []string{"masters", "workers"},
			commonnameTemplate:   "system:kube-proxy",
			organisationTemplate: "system:node-proxier",
			usages:               []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		},
		{
			path:               "/etc/kubernetes/pki/front-proxy-client",
			parent:             "/etc/kubernetes/pki/front-proxy-ca",
			nodes:              []string{"masters", "workers"},
			commonnameTemplate: "front-proxy-client",
			usages:             []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		},
		{
			path:               "/etc/kubernetes/pki/etcd/server",
			parent:             "/etc/kubernetes/pki/etcd/ca",
			nodes:              []string{"etcd"},
			commonnameTemplate: "{{.NodeName}}",
			usages:             []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			nodeSans:           true,
		},
		{
			path:               "/etc/kubernetes/pki/etcd/peer",
			parent:             "/etc/kubernetes/pki/etcd/ca",
			nodes:              []string{"etcd"},
			commonnameTemplate: "{{.NodeName}}",
			usages:             []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
			nodeSans:           true,
		},
		{
			path:                 "/etc/kubernetes/pki/etcd/etcd-healthcheck-client",
			parent:               "/etc/kubernetes/pki/etcd/ca",
			nodes:                []string{"masters"},
			commonnameTemplate:   "kube-etcd-healthcheck-client",
			organisationTemplate: "system:masters",
			usages:               []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		},
		{
			path:                 "/etc/kubernetes/pki/apiserver-etcd-client",
			parent:               "/etc/kubernetes/pki/etcd/ca",
			nodes:                []string{"masters"},
			commonnameTemplate:   "kube-apiserver-etcd-client",
			organisationTemplate: "system:masters",
			usages:               []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		},
	}
)

func renderStringTemplate(templateString string, data KubeTemplateData) string {
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

func makeSans(hosts KubeHostsAll, nodeType string, node string, apiSans bool, nodeSans bool, extraSans []string) (sans []string) {
	sans = make([]string, 0)
	if apiSans {
		for hostName, altSans := range hosts["apisans"] {
			sans = append(sans, hostName)
			sans = append(sans, altSans...)
		}
	}
	if nodeSans {
		sans = append(sans, defaultNodeSans...)
		sans = append(sans, node)
		sans = append(sans, hosts[nodeType][node]...)
	}
	if len(extraSans) > 0 {
		sans = append(sans, extraSans...)
	}
	return sans
}

func MakeKubeCertFromTemplate(hosts KubeHostsAll, template KubeCertTemplate, idx int, nodetype string, node string) (kc KubeCert, err error) {
	var sans []string
	var commonName string
	var organisation []string
	sans = makeSans(hosts, nodetype, node, template.apiSans, template.nodeSans, template.extraSans)
	commonName = renderStringTemplate(template.commonnameTemplate, KubeTemplateData{node})
	organisation = []string{renderStringTemplate(template.organisationTemplate, KubeTemplateData{node})}

	readStorage, err := storage.GetStorage(StorageReadType)
	if err != nil {
		panic("cant get storage driver")
	}

	writeStorage, err := storage.GetStorage(StorageWriteType)
	if err != nil {
		panic("cant get storage driver")
	}

	if node == "" {
		readStorage.SetConfigValue("basepath", filepath.Join(StorageReadLocation, GlobalPath))
		writeStorage.SetConfigValue("basepath", filepath.Join(StorageReadLocation, GlobalPath))
	} else {
		readStorage.SetConfigValue("basepath", filepath.Join(StorageReadLocation, NodesPath, node))
		writeStorage.SetConfigValue("basepath", filepath.Join(StorageReadLocation, NodesPath, node))
	}
	readStorage.SetConfigValue("filename", template.path)
	writeStorage.SetConfigValue("filename", template.path)

	kc = KubeCert{
		node:         node,
		commonName:   commonName,
		organisation: organisation,
		sans:         sans,
		templateIdx:  idx,
		readStorage:  readStorage,
		writeStorage: writeStorage,
	}

	return kc, nil
}

func RenderCertTemplates(hosts KubeHostsAll) (err error) {

	for idx, templateValues := range kubeCertTemplates {
		if len(templateValues.nodes) < 1 {
			kc, err := MakeKubeCertFromTemplate(hosts, templateValues, idx, "", "")
			if err != nil {
				log.Fatalf("Error making KubeCert from template %d", idx)
			}
			AllKubeCerts = append(AllKubeCerts, &kc)

		} else {
			for _, nodetype := range templateValues.nodes {
				if hosts[nodetype] == nil {
					continue
				}
				for node := range hosts[nodetype] {
					kc, err := MakeKubeCertFromTemplate(hosts, templateValues, idx, nodetype, node)
					if err != nil {
						log.Fatalf("Error making KubeCert from template %d", idx)
					}
					AllKubeCerts = append(AllKubeCerts, &kc)
				}
			}
		}
		//we assume the index ok last element appended to the slice is equal with slice len - 1
		// should check if we can relay on this behavior
		if templateValues.parent == "" {
			caIdx := len(AllKubeCerts) - 1
			KubeCAMap[templateValues.path] = caIdx
		}
	}
	return nil
}

func genCrt(crt *KubeCert) (err error) {

	crtConf := sslutil.NewCertConfig(365, crt.commonName, crt.organisation, crt.sans)

	if parent := kubeCertTemplates[crt.templateIdx].parent; parent == "" {
		crt.cert, crt.key, err = sslutil.SelfSignedCaKey(*crtConf, nil)
	} else {
		parentCrt := AllKubeCerts[KubeCAMap[parent]].cert
		parentKey := AllKubeCerts[KubeCAMap[parent]].key
		//pp.Print(parentKey)
		crt.cert, crt.key, err = sslutil.SelfSignedCertKey(*crtConf, parentCrt, parentKey, nil)
	}
	if err != nil {
		return fmt.Errorf("certificate: %q => %q\n", kubeCertTemplates[crt.templateIdx].path, err)
	}

	return nil
}

func genPEM(crt *KubeCert) (err error) {

	crt.certPEM = sslutil.EncodeCertPEM(crt.cert)
	if crt.certPEM == nil {
		return fmt.Errorf("error encoding certificate to PEM: %q", crt.commonName)
	}
	crt.keyPEM, err = keyutil.MarshalPrivateKeyToPEM(crt.key)
	if err != nil {
		return fmt.Errorf("error encoding key to PEM: %q", crt.commonName)
	}

	return nil
}

func writeCerts(crt *KubeCert) (err error) {
	crt.writeStorage.SetConfigValue("extension", ".crt")
	err = crt.writeStorage.Write(crt.certPEM)
	if err != nil {
		return fmt.Errorf("error writing file for cert: %q", crt.commonName)
	}
	crt.writeStorage.SetConfigValue("extension", ".key")
	err = crt.writeStorage.Write(crt.keyPEM)
	if err != nil {
		return fmt.Errorf("error writing file for key: %q", crt.commonName)
	}
	return nil
}

func Execute(apiSans *string, masters *string, workers *string) error {
	kubeHosts, err := get_kubehosts(apiSans, masters, workers)
	if err != nil {
		return err
	}
	err = RenderCertTemplates(*kubeHosts)
	if err != nil {
		return err
	}
	CheckCreateCerts()
	return nil
}

/*
	set_path based type
	if forceregen
		=> set failed // we check again in the end but we just skip steps
	if not failed
		=> try load key PEM
			=> if not succes
				=> set failed
	if not failed
		=> try load cert PEM
			=> if not succes
				=> set failed
	if not failed
		=> check cert signed by key
			=> if not succes
				=> set failed
	if not failed and not CA check cert validity against CA
		=> if not succes
			=> set failed
	if not failed
		=> check cert expiration
			=> if not succes
				=> set failed
	if not failed
		=> check template conformity
			=> if not succes
				=> set failed
	if forceregen || (failed && overwrite)
		=> gencrt
		=> write
	else
		=> panic/exit certfailed

*/

func CheckCreateCerts() (err error) {
	for _, crt := range AllKubeCerts {
		parent := kubeCertTemplates[crt.templateIdx].parent
		certname := kubeCertTemplates[crt.templateIdx].path

		if ForceRegen {
			crt.failed = "ForceRegen"
		}

		if crt.failed == "" {
			crt.readStorage.SetConfigValue("extension", ".crt")
			crt.certPEM, err = crt.readStorage.Read()
			if err != nil {
				fmt.Printf("%q\n", err)
				crt.failed = "error loading certificate"
			}
		}

		if crt.failed == "" {
			crt.readStorage.SetConfigValue("extension", ".key")
			crt.keyPEM, err = crt.readStorage.Read()
			if err != nil {
				fmt.Printf("%q\n", err)
				crt.failed = "error loading key"
			}
		}

		if crt.failed == "" {
			crt.cert, crt.key, err = sslutil.LoadCrtAndKeyFromPEM(crt.certPEM, crt.keyPEM)
			if err != nil {
				fmt.Printf("%q\n", err)
				crt.failed = "error loading cert or key from PEM format"
			}
		}

		if crt.failed == "" && parent == "" {
			err = sslutil.VerifyCrtSignature(crt.cert, crt.key)
			if err != nil {
				fmt.Printf("%q\n", err)
				crt.failed = "error verifying cert signature"
			}
		}

		if crt.failed == "" && parent != "" {
			err = crt.cert.CheckSignatureFrom(AllKubeCerts[KubeCAMap[parent]].cert)
			if err != nil {
				fmt.Printf("%q\n", err)
				crt.failed = "cert not emitted by parent CA"
			}
		}
		if crt.failed != "" {
			fmt.Printf("crt: %q error: %q\n", certname, crt.failed)
		}
		if ForceRegen || (crt.failed != "" && OverWrite) {
			err = genCrt(crt)
			if err != nil {
				return err
			}
			genPEM(crt)
			if err != nil {
				return err
			}

			writeCerts(crt)
			if err != nil {
				return err
			}
		} else if crt.failed == "" {
			fmt.Printf("CRT OK\n")
			continue
		} else {
			fmt.Printf("%t %q %t\n", ForceRegen, crt.failed, OverWrite)
			panic("certificate check failed and OverWrite forbidden")
		}

	}
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

	return &kh, err
}
