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

package kubekeys

import (
	"bytes"
	"fmt"
	"k8s.io/client-go/util/keyutil"
	"path/filepath"
	"sslutil"
	"storage"
)

type KubeKeyTemplate struct {
	path  string
	nodes []string
}

type KubeKey struct {
	key          interface{}
	keyPrivPEM   []byte
	keyPubPEM    []byte
	templateIdx  int
	readStorage  storage.StoreDrv
	writeStorage storage.StoreDrv
	failed       string
}

var (
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

	KubeKeyTemplates = []KubeKeyTemplate{
		{
			path: "/etc/kubernetes/pki/sa",
		},
	}
	AllKubeKeys []*KubeKey
)

func MakeKeyFromTemplate(tpl KubeKeyTemplate, idx int) (kubeKey KubeKey, err error) {

	readStorage, err := storage.GetStorage(StorageReadType)
	if err != nil {
		panic("cant get storage driver")
	}

	writeStorage, err := storage.GetStorage(StorageWriteType)
	if err != nil {
		panic("cant get storage driver")
	}

	readStorage.SetConfigValue("basepath", filepath.Join(StorageReadLocation, GlobalPath))
	writeStorage.SetConfigValue("basepath", filepath.Join(StorageReadLocation, GlobalPath))
	readStorage.SetConfigValue("filename", tpl.path)
	writeStorage.SetConfigValue("filename", tpl.path)

	kubeKey = KubeKey{
		key:          nil,
		keyPrivPEM:   nil,
		keyPubPEM:    nil,
		templateIdx:  idx,
		readStorage:  readStorage,
		writeStorage: writeStorage,
	}
	return kubeKey, nil
}

func renderKeys() (err error) {
	for idx, templateValues := range KubeKeyTemplates {
		kk, err := MakeKeyFromTemplate(templateValues, idx)
		if err != nil {
			return err
		}
		AllKubeKeys = append(AllKubeKeys, &kk)
	}
	return nil
}

func genKey(k *KubeKey) (err error) {
	k.key, err = sslutil.NewPrivateKey("")
	return nil
}

func genPEM(k *KubeKey) (err error) {

	pub := sslutil.PublicKey(k.key)
	k.keyPubPEM, _ = sslutil.EncodePublicKeyPEM(pub)
	k.keyPrivPEM, _ = sslutil.MarshalPrivateKeyToPEM(k.key)
	return nil
}

func writeCerts(key *KubeKey) (err error) {
	key.writeStorage.SetConfigValue("extension", ".pub")
	err = key.writeStorage.Write(key.keyPubPEM)
	if err != nil {
		return fmt.Errorf("error writing file for public key")
	}
	key.writeStorage.SetConfigValue("extension", ".key")
	err = key.writeStorage.Write(key.keyPrivPEM)
	if err != nil {
		return fmt.Errorf("error writing file for private key")
	}
	return nil
}

func CheckCreateKeys() (err error) {
	_ = renderKeys()
	for _, key := range AllKubeKeys {

		template := KubeKeyTemplates[key.templateIdx]

		keyname := template.path

		if ForceRegen {
			key.failed = "ForceRegen"
		}

		if key.failed == "" {
			key.readStorage.SetConfigValue("extension", ".key")
			key.keyPrivPEM, err = key.readStorage.Read()
			if err != nil {
				key.failed = "error loading public key"
			}
		}

		if key.failed == "" {
			key.readStorage.SetConfigValue("extension", ".pub")
			key.keyPubPEM, err = key.readStorage.Read()
			if err != nil {
				key.failed = "error private key"
			}
		}

		if key.failed == "" {
			key.key, err = keyutil.ParsePrivateKeyPEM(key.keyPrivPEM)
			if err != nil {
				key.failed = "error private key from pem"
			}

		}

		if key.failed == "" {
			pub := sslutil.PublicKey(key.key)
			tempPEM, _ := sslutil.EncodePublicKeyPEM(pub)
			if !bytes.Equal(tempPEM, key.keyPubPEM) {
				key.failed = "error public and private keys do not match"
			}
		}

		if key.failed != "" {
			fmt.Printf("KEY ERROR  : [%-30s] [%-50s] => %q\n", "", keyname, key.failed)
		}
		if ForceRegen || (key.failed != "" && OverWrite) {
			err = genKey(key)
			if err != nil {
				return err
			}
			err = genPEM(key)
			if err != nil {
				return err
			}

			err = writeCerts(key)
			if err != nil {
				return err
			}
			fmt.Printf("KEY WRITTEN: [%-30s] [%-50s]\n", "", keyname)
		} else if key.failed == "" {
			fmt.Printf("KEY OK     : [%-30s] [%-50s]\n", "", keyname)
			continue
		} else {
			fmt.Printf("%t %q %t\n", ForceRegen, key.failed, OverWrite)
			panic("certificate check failed and OverWrite forbidden")
		}

	}
	return nil

}
