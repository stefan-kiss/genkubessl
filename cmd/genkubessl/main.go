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
	"kubecerts"
	"kubekeys"
	"os"
)

//var (
//	cacn      = flag.String("cacn", "kubernetes", "CA CommonName")
//	certcn    = flag.String("certnc", "kubernetes", "Cert CommonName")
//	certhosts = flag.String("hosts", "", "Coma separated hostnames and ip's to be included in altnames")
//)

var (
	changed int
)

const (
	Usage = `
commands:
	kubecerts	generates kubernetes mtls certificates
	extcerts	generates external certs (e.g. certs used by ingress - if used at all)

Use
	./kubecerts [command] -h
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
	BasePathHelp = `base path for storage`
)

func printusage() {
	fmt.Print(Usage)
}

func main() {

	kubecertsCmd := flag.NewFlagSet("kubecerts", flag.ExitOnError)
	apisans := kubecertsCmd.String("apisans", "", ApiSansHelp)
	masters := kubecertsCmd.String("masters", "", MastersHelp)
	workers := kubecertsCmd.String("workers", "", WorkersHelp)
	etcd := kubecertsCmd.String("etcd", "", EtcdHelp)
	users := kubecertsCmd.String("users", "", UsersHelp)
	basepath := kubecertsCmd.String("basepath", "", BasePathHelp)
	extcertsCmd := flag.NewFlagSet("extcerts", flag.ExitOnError)

	if len(os.Args) < 2 {
		printusage()
		os.Exit(2)
	} else {
		switch os.Args[1] {
		case "kubecerts":
			kubecertsCmd.Parse(os.Args[2:])
			kkonfig := kubecerts.Cfg{
				Apisans: apisans,
				Masters: masters,
				Workers: workers,
				Etcd:    etcd,
				Users:   users,
			}
			fmt.Printf("CERTS =>>\n")
			if *basepath != "" {
				kubecerts.StorageReadLocation = *basepath
				kubecerts.StorageWriteLocation = *basepath
			}
			_ = kubecerts.Execute(kkonfig)
			fmt.Printf("KEYS =>>\n")

			if *basepath != "" {
				kubekeys.StorageReadLocation = *basepath
				kubekeys.StorageWriteLocation = *basepath
			}
			_ = kubekeys.CheckCreateKeys()
			if kubecerts.Changed == 1 || kubekeys.Changed == 1 {
				fmt.Printf("\nCHANGED: TRUE\n")
			} else {
				fmt.Printf("\nCHANGED: FALSE\n")
			}
			os.Exit(0)
		case "extcerts":
			extcertsCmd.Parse(os.Args[2:])
		default:
			fmt.Printf("%q is not valid command.\n", os.Args[1])
			printusage()
			os.Exit(2)
		}
	}
	os.Exit(0)
}
