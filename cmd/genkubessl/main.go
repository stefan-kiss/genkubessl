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

package main

import (
	"flag"
	"fmt"
	"github.com/stefan-kiss/genkubessl/internal/config"
	"github.com/stefan-kiss/genkubessl/internal/kubecerts"
	"github.com/stefan-kiss/genkubessl/internal/kubekeys"
	"github.com/stefan-kiss/genkubessl/internal/storage"
	"log"
	"os"
	"path/filepath"
)

//var (
//	cacn      = flag.String("cacn", "kubernetes", "CA CommonName")
//	certcn    = flag.String("certnc", "kubernetes", "Cert CommonName")
//	certhosts = flag.String("hosts", "", "Coma separated hostnames and ip's to be included in altnames")
//)

const (
	Usage = `
./genkubessl [-src source] [-dst destination] [command] [parameters...]
commands:
	kubecerts	generates kubernetes mtls certificates
	cacert	    generates generate a ca and signed cert
	nakedcert   generates a 'naked' self-signed certificate

Use
./genkubessl [-src source] [-dst destination] [command] -h
to show additional help

`
	ApiSansHelp = `
MANDATORY
format: < main host[/extra names or extra ip's[:...]] >
main api host as well as any extra list of additional hostnames or ip addresses separated by colon

standard kubernetes api dns names will be automatically added.

Example: "kapi.example.org/10.0.0.1,127.0.0.1"	
`
	MastersHelp = `
MANDATORY
format: < node[/extra names or extra ip's[:...]] >[,node[/extra names or extra ip's[:...]]][,...]

MASTER node blocks separated by comma
can contain additional hostnames or ip's' separated by colons
Example: "master01.example.org/10.0.0.1:10.0.0.2,master02.example.org/10.0.1.1:10.0.1.2"

note: hostnames and ip's will be automatically added to apis altnames
note: first name for each node will be considered the node name (the hostname used by kubernetes to identify the host) 
`
	WorkersHelp = `
MANDATORY
comma separated list of colon separated hostnames and ip's for each WORKER node
format: < node[/extra names or extra ip's[:...]] >[,node[/extra names or extra ip's[:...]]][,...]

WORKER node blocks separated by comma
can contain additional hostnames or ip's' separated by colons

Example: "worker01.example.org/10.1.0.1:10.1.0.2,worker02.example.org/10.1.1.1:10.1.1.2"
note: first name for each node will be considered the node name (the hostname used by kubernetes to identify the host)
`
	EtcdHelp = `
OPTIONAL. If missing master nodes will be used instead
comma separated list of colon separated hostnames and ip's for each ETCD node
format: < node[/extra names or extra ip's[:...]] >[,node[/extra names or extra ip's[:...]]][,...]

ETCD node blocks separated by comma
can contain additional hostnames or ip's' separated by colons

Example: "etcd01.example.org/10.1.0.1:10.1.0.2,etcd02.example.org/10.1.1.1:10.1.1.2"
note: first name for each node will be considered the node name (the hostname used by kubernetes to identify the host)
`
	UsersHelp = `
OPTIONAL. If missing admin user will be created
comma separated list of <user:group>
format: <user/group>[,user/group]...

Example: "bob.john/admin-users,andrew.lewis/read-only,thomas.johnson/test-group"
note: this only creates certificates for the users, any RBAC rules you have to set separately
`
	DestinationUrlHelp = `
URL describing the location where to store the generated certificates
if schema is missing it is interpreted as a file path
Default "outputs/system"
`
	SourceUrlHelp = `
URL describing the location where to get the existing (if any) ca's and certificates'
if schema is missing it is interpreted as a file path
if missing it will be set to the same value as destination url (-dest flag)
`
)

func printusage(set *flag.FlagSet) {
	fmt.Print(Usage)
	if set != nil {
		set.Usage()
	} else {
		flag.Usage()
	}
	os.Exit(2)
}

func main() {
	var err error

	src := flag.String("src", "", SourceUrlHelp)
	dst := flag.String("dst", "outputs/system", DestinationUrlHelp)

	kubecertsCmd := flag.NewFlagSet("kubecerts", flag.ExitOnError)
	cacrtCmd := flag.NewFlagSet("cacert", flag.ExitOnError)
	nakedcrtCmd := flag.NewFlagSet("nakedcert", flag.ExitOnError)
	nodecertsCmd := flag.NewFlagSet("nodecerts", flag.ExitOnError)
	userconfigCmd := flag.NewFlagSet("userconfig", flag.ExitOnError)

	flag.Parse()

	if len(flag.Args()) < 1 {
		printusage(nil)

	}
	// TODO handle Parse() errors
	switch flag.Arg(0) {
	case "kubecerts":
		apisans := kubecertsCmd.String("apisans", "", ApiSansHelp)
		masters := kubecertsCmd.String("masters", "", MastersHelp)
		workers := kubecertsCmd.String("workers", "", WorkersHelp)
		etcd := kubecertsCmd.String("etcd", "", EtcdHelp)
		users := kubecertsCmd.String("users", "", UsersHelp)

		err = kubecertsCmd.Parse(flag.Args()[1:])
		if err != nil {
			printusage(kubecertsCmd)
		}
		ClusterConfig := kubecerts.ClusterConfig{
			Apisans: apisans,
			Masters: masters,
			Workers: workers,
			Etcd:    etcd,
			Users:   users,
		}
		fmt.Printf("CERTS =>>\n")
		if *src == "" {
			*src = *dst
		}
		// TODO
		cwd, _ := os.Getwd()

		if !filepath.IsAbs(*src) {
			*src = filepath.Join(cwd, *src)
		}

		if !filepath.IsAbs(*dst) {
			*dst = filepath.Join(cwd, *dst)
		}
		wrd, err := storage.GetStorage(*dst)
		if err != nil {
			log.Fatalf("error getting storage driver for %s: %v", *dst, err)
		}
		rdd, err := storage.GetStorage(*src)
		if err != nil {
			log.Fatalf("error getting storage driver for %s: %v", *src, err)
		}

		GlobalConfig := config.GlobalConfig{
			WriteDriver: wrd,
			ReadDriver:  rdd,
		}

		_ = kubecerts.Execute(GlobalConfig, ClusterConfig)
		fmt.Printf("KEYS =>>\n")

		_ = kubekeys.CheckCreateKeys(GlobalConfig)
		if kubecerts.Changed || kubekeys.Changed {
			fmt.Printf("\nGLOBAL_CHANGED: TRUE\n")
		} else {
			fmt.Printf("\nGLOBAL_CHANGED: FALSE\n")
		}
		os.Exit(0)
	case "nodecerts":
		err = nodecertsCmd.Parse(flag.Args()[1:])
		if err != nil {
			printusage(nodecertsCmd)
		}
		os.Exit(0)
	case "cacert":
		err = cacrtCmd.Parse(flag.Args()[1:])
		if err != nil {
			printusage(cacrtCmd)
		}

		os.Exit(0)
	case "nakedcert":
		err = nakedcrtCmd.Parse(flag.Args()[1:])
		if err != nil {
			printusage(nakedcrtCmd)
		}
		os.Exit(0)
	case "userconfig":
		err = userconfigCmd.Parse(flag.Args()[1:])
		if err != nil {
			printusage(userconfigCmd)
		}
		os.Exit(0)
	default:
		fmt.Printf("%q is not valid command.\n", os.Args[1])
		printusage(nil)
		os.Exit(2)
	}
	os.Exit(0)
}
