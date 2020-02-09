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

package file

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path"
	"path/filepath"
	"strconv"
)

type StoreFile struct {
	config map[string]string
}

func NewDefaultsStoreFile() *StoreFile {

	config := make(map[string]string)
	config["root"] = ""
	config["makeRoot"] = "true"
	config["basepath"] = "outputs/external/default"
	config["makebase"] = "true"
	config["filename"] = ""
	config["extension"] = ""
	config["dirmode"] = "0744"
	config["filemode"] = "0600"
	config["owner"] = ""
	return &StoreFile{config: config}
}

func (s *StoreFile) Read() (cert []byte, err error) {

	filename := s.config["filename"] + s.config["extension"]
	fullpath := path.Join(s.config["root"], s.config["basepath"], filename)

	if _, err := os.Stat(fullpath); err != nil {
		return nil, fmt.Errorf("cannot read file: %s", fullpath)
	}

	return ioutil.ReadFile(fullpath)
}

func (s *StoreFile) Write(cert []byte) (err error) {
	dirmode, err := strconv.Atoi(s.config["dirmode"])
	//dirmode, err = strconv.ParseUint(s.config["dirmode"], 8, 32)
	if err != nil {
		dirmode = 0755
	}
	// TODO: fix
	// override until i figure out a way to get correct mode out of string
	dirmode = 0755

	filemode, err := strconv.Atoi(s.config["filemode"])
	if err != nil {
		filemode = 0600
	}
	// TODO: fix
	// override until i figure out a way to get correct mode out of string
	filemode = 0600

	filedir := filepath.Dir(s.config["filename"])
	filename := filepath.Base(s.config["filename"]) + s.config["extension"]

	basepath := path.Join(s.config["root"], s.config["basepath"], filedir)
	fullpath := path.Join(basepath, filename)

	if _, err := os.Stat(basepath); err != nil {
		if s.config["makebase"] != "" {
			err = os.MkdirAll(basepath, os.FileMode(dirmode))
			if err != nil {
				log.Fatalf("cant make dir: %q\n", basepath)
			}
		} else {
			return fmt.Errorf("basepath directory: %s does not exist", basepath)
		}
	}

	if _, err := os.Stat(fullpath); err != nil {
		err = os.Remove(fullpath)
	}
	if err != nil {
		return err
	}

	return ioutil.WriteFile(fullpath, cert, os.FileMode(filemode))
}

func (s *StoreFile) SetConfigValue(key string, value string) {
	s.config[key] = value
}
