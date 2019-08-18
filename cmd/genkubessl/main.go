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
	"os"
	"sslutil"
	"storage"
	"storage/file"
	"strings"
)

var (
	cacn      = flag.String("cacn", "kubernetes", "CA CommonName")
	certcn    = flag.String("certnc", "kubernetes", "Cert CommonName")
	certhosts = flag.String("hosts", "", "Coma separated hostnames and ip's to be included in altnames")
)

func main() {

	flag.Parse()

	org := []string{"kubernetes"}

	caconf := *sslutil.NewCAConfig(30, *cacn, org, nil)

	cakey, err := sslutil.NewPrivateKey("")
	if err != nil {
		fmt.Printf("error generating new private key: %s", err)
		os.Exit(-1)
	}

	ca, cakey, err := sslutil.NewSelfSignedCACert(caconf, nil)
	if err != nil {
		fmt.Printf("error generating new ca: %s", err)
		os.Exit(-1)
	}

	altnames := strings.Split(*certhosts, ",")
	crtconf := *sslutil.NewCAConfig(30, "kubernetes", org, altnames)
	crtconf.Locality = []string{"Bucharest"}
	crtconf.Country = []string{"Romania"}
	if err != nil {
		fmt.Printf("error generating new private key: %s", err)
		os.Exit(-1)
	}
	cert, certkey, err := sslutil.GenerateSelfSignedCertKey(crtconf, ca, cakey, nil)

	capem := sslutil.EncodeCertPEM(ca)
	certpem := sslutil.EncodeCertPEM(cert)

	cakeypem, err1 := sslutil.MarshalPrivateKeyToPEM(cakey)
	certkeypem, err2 := sslutil.MarshalPrivateKeyToPEM(certkey)

	fmt.Printf("capem\n%s\n", capem)
	fmt.Printf("certpem\n%s\n", certpem)
	fmt.Printf("cakeypem\n%s\n%s\n", cakeypem, err1)
	fmt.Printf("certkeypem\n%s\n%s\n", certkeypem, err2)

	var storeFile = file.NewDefaultsStoreFile()
	var s storage.StoreDrv = storeFile

	storeFile.Filename = "ca"
	storeFile.Extension = ".crt"
	_ = s.Write(capem)

	storeFile.Filename = "ca"
	storeFile.Extension = ".key"
	_ = s.Write(cakeypem)

	storeFile.Filename = "cert"
	storeFile.Extension = ".crt"
	_ = s.Write(certpem)

	storeFile.Filename = "cert"
	storeFile.Extension = ".key"
	_ = s.Write(certkeypem)

}
