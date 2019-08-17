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
	"os"
	"path"
)

type StoreFile struct {
	Root  string
	Basepath string
	Filename  string
	Extension string
	MakeRoot bool
	MakeBase bool
	Dirmode os.FileMode
	Filemode os.FileMode
	Owner string

}

func NewDefaultsStoreFile() *StoreFile {
	return &StoreFile{
		Root: "",
		MakeRoot: true,

		Basepath: "outputs/external/default",
		MakeBase: true,

		Filename: "",
		Extension: "",
		Dirmode: 0744,
		Filemode: 0600,
		Owner: "",
	}
}

func (s *StoreFile) Read() (cert []byte, err error) {

	filename := s.Filename + s.Extension
	fullpath := path.Join(s.Root,s.Basepath,filename)

	if _, err := os.Stat(fullpath); err != nil {
		return nil,fmt.Errorf("cannot read file: %s does not exist",fullpath)
	}

	return ioutil.ReadFile(fullpath)
}


func (s *StoreFile) Write(cert []byte) (err error) {
	filename := s.Filename + s.Extension
	basepath := path.Join(s.Root,s.Basepath)
	fullpath := path.Join(s.Root,s.Basepath,filename)

	if s.Root != "" {
		if _, err := os.Stat(s.Root); err != nil {
			if s.MakeRoot {
				os.MkdirAll(s.Root,s.Dirmode)
			} else {
				return fmt.Errorf("root directory does not exist: %s does not exist", s.Root)
			}
		}

	}
	if s.Basepath != "" {
		if _, err := os.Stat(basepath); err != nil {
			if s.MakeRoot {
				os.MkdirAll(basepath,s.Dirmode)
			} else {
				return fmt.Errorf("basepath directory: %s does not exist", basepath)
			}
		}

	}


	return ioutil.WriteFile(fullpath, cert, s.Filemode)
}
