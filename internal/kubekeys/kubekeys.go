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
	"github.com/stefan-kiss/genkubessl/internal/config"
	"github.com/stefan-kiss/genkubessl/internal/sslutil"
	"path/filepath"
)

type KubeKeyTemplate struct {
	path  string
	nodes []string
}

type KubeKey struct {
	key         interface{}
	keyPrivPEM  []byte
	keyPubPEM   []byte
	templateIdx int
	readPath    string
	writePath   string
	failed      string
}

const (
	ForceRegen = false
	// overwrite if fails checks
	OverWrite = true

	// storage related // hardcoded for now
	GlobalPath = "global"
	NodesPath  = "nodes"
)

var (
	// TODO return value rather than use global
	Changed = false

	KubeKeyTemplates = []KubeKeyTemplate{
		{
			path: "/etc/kubernetes/pki/sa",
		},
	}
	AllKubeKeys []*KubeKey
)

func MakeKeyFromTemplate(GlobalCfg config.GlobalConfig, tpl KubeKeyTemplate, idx int) (kubeKey KubeKey, err error) {

	var readPath, writePath string

	readPath = filepath.Join(GlobalPath, tpl.path)
	writePath = filepath.Join(GlobalPath, tpl.path)

	kubeKey = KubeKey{
		key:         nil,
		keyPrivPEM:  nil,
		keyPubPEM:   nil,
		templateIdx: idx,
		readPath:    readPath,
		writePath:   writePath,
	}
	return kubeKey, nil
}

func renderKeys(GlobalCfg config.GlobalConfig) (err error) {
	for idx, templateValues := range KubeKeyTemplates {
		kk, err := MakeKeyFromTemplate(GlobalCfg, templateValues, idx)
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

func writeCerts(GlobalCfg config.GlobalConfig, key *KubeKey) (err error) {

	err = GlobalCfg.WriteDriver.Write(key.writePath+".pub", key.keyPubPEM)
	if err != nil {
		return fmt.Errorf("error writing file for public key")
	}
	err = GlobalCfg.WriteDriver.Write(key.writePath+".key", key.keyPrivPEM)
	if err != nil {
		return fmt.Errorf("error writing file for private key")
	}
	return nil
}

func CheckCreateKeys(GlobalCfg config.GlobalConfig) (err error) {

	_ = renderKeys(GlobalCfg)
	for _, key := range AllKubeKeys {

		tpl := KubeKeyTemplates[key.templateIdx]

		keyname := tpl.path

		if ForceRegen {
			key.failed = "ForceRegen"
		}

		if key.failed == "" {

			key.keyPrivPEM, err = GlobalCfg.ReadDriver.Read(key.readPath + ".key")
			if err != nil {
				key.failed = "error loading public key"
			}
		}

		if key.failed == "" {
			key.keyPubPEM, err = GlobalCfg.ReadDriver.Read(key.readPath + ".pub")
			if err != nil {
				key.failed = "error private key"
			}
		}

		if key.failed == "" {
			key.key, err = sslutil.ParsePrivateKeyPEM(key.keyPrivPEM)
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

			err = writeCerts(GlobalCfg, key)
			if err != nil {
				return err
			}
			fmt.Printf("KEY WRITTEN: [%-30s] [%-50s]\n", "", keyname)
			Changed = true
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
