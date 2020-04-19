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
)

type StoreFile struct {
	RootPath    string
	MakeRoot    bool
	MakeDirs    bool
	RootDirMode os.FileMode
	DirMode     os.FileMode
	FileMode    os.FileMode
	Owner       string
	Group       string
}

func NewStoreFile(rootPath string) *StoreFile {

	return &StoreFile{
		RootPath:    rootPath,
		MakeRoot:    true,
		MakeDirs:    true,
		RootDirMode: 0755,
		DirMode:     0755,
		FileMode:    0600,
		Owner:       "",
		Group:       "",
	}
}

func checkMakeDir(directory string, makeIt bool, mode os.FileMode) (err error) {
	if _, err = os.Stat(directory); err != nil {
		if !makeIt {
			return fmt.Errorf("base directory does not exist we are set not to create it: %s :%v\n", directory, err)
		}
		err = os.MkdirAll(directory, mode)
		if err != nil {
			log.Fatalf("cant make dir: %q\n", directory)
		}
	}
	return nil
}

func (s *StoreFile) Read(filePath string) (content []byte, err error) {

	fullpath := path.Join(s.RootPath, filePath)

	if _, err := os.Stat(fullpath); err != nil {
		return nil, fmt.Errorf("cannot read file: %s", fullpath)
	}

	return ioutil.ReadFile(fullpath)
}

func (s *StoreFile) Write(filePath string, content []byte) (err error) {
	//dirmode, err := strconv.ParseUint(s.config["dirmode"], 8, 32)
	//if err != nil {
	//	dirmode = 0755
	//}

	//filemode, err := strconv.ParseUint(s.config["filemode"], 8, 32)
	//if err != nil {
	//	filemode = 0600
	//}
	err = checkMakeDir(s.RootPath, s.MakeRoot, s.RootDirMode)
	if err != nil {
		return err
	}
	fileFullPath := filepath.Join(s.RootPath, filePath)
	fileDirPath := filepath.Dir(fileFullPath)
	err = checkMakeDir(fileDirPath, s.MakeDirs, s.DirMode)
	if err != nil {
		return err
	}

	if _, err := os.Stat(fileFullPath); err != nil {
		err = os.Remove(fileFullPath)
	}
	if err != nil {
		return err
	}

	return ioutil.WriteFile(fileFullPath, content, s.FileMode)
}

func (s *StoreFile) SetConfigValue(key string, value string) {
	return
}

func (s *StoreFile) LoadConfig(filepath string) (err error) {
	return nil
}
