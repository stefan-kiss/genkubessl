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
	"github.com/k0kubun/pp"
	"github.com/stefan-kiss/genkubessl/internal/config"
	"github.com/stefan-kiss/genkubessl/internal/sslutil"
	"github.com/stefan-kiss/genkubessl/internal/storage"
	"github.com/stefan-kiss/genkubessl/internal/util"
	"log"
	"path/filepath"
	"reflect"
	"strings"
	"text/template"
	"time"
)

type ClusterConfig struct {
	Apisans    *string
	Masters    *string
	Workers    *string
	Etcd       *string
	Users      *string
	InStorage  storage.StoreDrv
	OutStorage storage.StoreDrv
}

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
	failed       string
	readPath     string
	writePath    string
}

const (

	// Behavior for dealing with existing certificates. currently hardcoded.
	ForceRegen = false
	// overwrite if fails checks
	OverWrite = true

	GlobalPath = "global"
	NodesPath  = "nodes"

	// hardcoded min duration
	CheckCertMinValid = time.Hour * 24 * 10
)

var (
	// TODO return value rather than use global
	Changed = false

	defaultNodeSans = []string{"127.0.0.1", "localhost", "::1"}

	KubeCAMap    = make(map[string]int)
	AllKubeCerts = make([]*KubeCert, 0)

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

// not very performant but we want unique San's
func makeSans(hosts KubeHostsAll, nodeType string, node string, apiSans bool, nodeSans bool, extraSans []string) (sans []string) {
	// empty map for uniqueness
	sansMAP := make(map[string]struct{})

	if apiSans {
		for hostName, altSans := range hosts["apisans"] {
			sansMAP[hostName] = struct{}{}
			for _, altName := range altSans {
				sansMAP[altName] = struct{}{}
			}
		}
	}
	if nodeSans {
		sansMAP[node] = struct{}{}
		for _, altName := range defaultNodeSans {
			sansMAP[altName] = struct{}{}
		}
		for _, altName := range hosts[nodeType][node] {
			sansMAP[altName] = struct{}{}
		}
	}
	if len(extraSans) > 0 {
		for _, altName := range extraSans {
			sansMAP[altName] = struct{}{}
		}
	}
	for san, _ := range sansMAP {
		sans = append(sans, san)
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
	if reflect.DeepEqual(organisation, []string{""}) {
		organisation = []string{}
	}

	var readPath, writePath string

	if node == "" {
		readPath = filepath.Join(GlobalPath, template.path)
		writePath = filepath.Join(GlobalPath, template.path)
	} else {
		readPath = filepath.Join(NodesPath, node, template.path)
		writePath = filepath.Join(NodesPath, node, template.path)
	}

	kc = KubeCert{
		node:         node,
		commonName:   commonName,
		organisation: organisation,
		sans:         sans,
		templateIdx:  idx,
		readPath:     readPath,
		writePath:    writePath,
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

	crtConf := sslutil.NewCertConfig(0, crt.commonName, crt.organisation, crt.sans)

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
	crt.keyPEM, err = sslutil.MarshalPrivateKeyToPEM(crt.key)
	if err != nil {
		return fmt.Errorf("error encoding key to PEM: %q", crt.commonName)
	}

	return nil
}

func writeCerts(GlobalCfg config.GlobalConfig, crt *KubeCert) (err error) {
	err = GlobalCfg.WriteDriver.Write(crt.writePath+".crt", crt.certPEM)
	if err != nil {
		return fmt.Errorf("error writing file for cert: %q", crt.commonName)
	}
	err = GlobalCfg.WriteDriver.Write(crt.writePath+".key", crt.keyPEM)
	if err != nil {
		return fmt.Errorf("error writing file for cert: %q", crt.commonName)
	}
	return nil
}

func cmpWithDefinition(crt *x509.Certificate, def *KubeCert) (err error) {
	if crt.Subject.CommonName != def.commonName {
		return fmt.Errorf("mismatching CommonName")
	}
	if err = util.UniqueStringSliceCmp(crt.Subject.Organization, def.organisation); err != nil {
		return fmt.Errorf("mismatching Organisation")
	}
	// add more Subject fields as necessary. currently kubernetes does not use others

	if err = util.UniqueStringSliceCmp(sslutil.GetAllSans(crt), def.sans); err != nil {

		fmt.Printf("Cert Sans: ")
		pp.Print(sslutil.GetAllSans(crt))
		fmt.Printf("\n")
		fmt.Printf("Def Sans: ")
		pp.Print(def.sans)
		fmt.Printf("\n")

		return fmt.Errorf("mismatching AltNames")
	}
	return nil
}

func Execute(GlobalCfg config.GlobalConfig, ClusterConfig ClusterConfig) error {

	kubeHosts, err := getKubehosts(ClusterConfig.Apisans, ClusterConfig.Masters, ClusterConfig.Workers, ClusterConfig.Etcd)
	if err != nil {
		return err
	}

	_ = getUsers(ClusterConfig.Users)

	err = RenderCertTemplates(*kubeHosts)
	if err != nil {
		return err
	}

	err = CheckCreateCerts(GlobalCfg)
	if err != nil {
		log.Fatal(err)
	}
	return nil
}

func CheckCreateCerts(GlobalConfig config.GlobalConfig) (err error) {
	for _, crt := range AllKubeCerts {

		tpl := kubeCertTemplates[crt.templateIdx]

		parent := tpl.parent
		certname := tpl.path

		if ForceRegen {
			crt.failed = "ForceRegen"
		}

		if crt.failed == "" {
			crt.certPEM, err = GlobalConfig.ReadDriver.Read(crt.readPath + ".crt")
			if err != nil {
				crt.failed = "error loading certificate"
			}
		}

		if crt.failed == "" {
			crt.keyPEM, err = GlobalConfig.ReadDriver.Read(crt.readPath + ".key")
			if err != nil {
				crt.failed = "error loading certificate"
			}
		}

		if crt.failed == "" {
			crt.cert, crt.key, err = sslutil.LoadCrtAndKeyFromPEM(crt.certPEM, crt.keyPEM)
			if err != nil {
				crt.failed = "error loading cert or key from PEM format"
			}
		}

		if crt.failed == "" && parent == "" {
			err = sslutil.VerifyCrtSignature(crt.cert, crt.key)
			if err != nil {
				crt.failed = "error verifying cert signature"
			}
		}

		if crt.failed == "" && parent != "" {
			err = crt.cert.CheckSignatureFrom(AllKubeCerts[KubeCAMap[parent]].cert)
			if err != nil {
				crt.failed = "cert not emitted by parent CA"
			}
		}

		if crt.failed == "" {
			err = cmpWithDefinition(crt.cert, crt)
			if err != nil {
				crt.failed = "cert not emitted according to definition"
			}
		}

		if crt.failed != "" {
			fmt.Printf("CRT ERROR  : [%-30s] [%-50s] => %q\n", crt.node, certname, crt.failed)
		}
		if ForceRegen || (crt.failed != "" && OverWrite) {
			err = genCrt(crt)
			if err != nil {
				return err
			}
			err = genPEM(crt)
			if err != nil {
				return err
			}

			err = writeCerts(GlobalConfig, crt)
			if err != nil {
				return err
			}
			fmt.Printf("CRT WRITTEN: [%-30s] [%-50s]\n", crt.node, certname)
			Changed = true
		} else if crt.failed == "" {
			fmt.Printf("CRT OK     : [%-30s] [%-50s]\n", crt.node, certname)
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
func getUsers(users *string) (err error) {
	usergroups := strings.Split(*users, ",")
	var kubeUser string
	var kubeGroup string
	for _, ug := range usergroups {
		user_gr := strings.Split(ug, "/")
		if len(user_gr) < 2 {
			fmt.Printf("invalid user: %q", ug)
			continue
		}
		kubeUser = user_gr[0]
		kubeGroup = user_gr[1]
		kubeCertTemplates = append(kubeCertTemplates, KubeCertTemplate{
			path:                 "/etc/kubernetes/pki/users/" + kubeUser,
			usages:               []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			parent:               "/etc/kubernetes/pki/ca",
			commonnameTemplate:   kubeUser,
			organisationTemplate: kubeGroup,
		})
	}
	return nil
}
func getKubehosts(apisans *string, masters *string, workers *string, etcd *string) (cluster *KubeHostsAll, err error) {

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

	wrk, err := parsesans(workers, false)
	if err != nil {
		return nil, err
	}
	kh["workers"] = wrk

	etc, err := parsesans(etcd, false)

	if err == nil {
		kh["etcd"] = etc
	} else {
		kh["etcd"] = mst
	}

	return &kh, nil
}
