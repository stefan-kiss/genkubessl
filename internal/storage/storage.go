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

package storage

import (
	"fmt"
	"github.com/stefan-kiss/genkubessl/internal/storage/file"
	"log"
	"net/url"
)

type StoreDrv interface {
	Write(filePath string, cert []byte) (err error)
	Read(filePath string) (cert []byte, err error)
	SetConfigValue(key string, value string)
	LoadConfig(filepath string) (err error)
}

func GetStorage(storageURL string) (storage StoreDrv, err error) {

	parsedURL, err := url.Parse(storageURL)
	if err != nil {
		log.Fatalf("unable to parse url: %v error:", err)
	}
	switch parsedURL.Scheme {
	case "", "file":
		return file.NewStoreFile(parsedURL.Path), nil
	default:
		return nil, fmt.Errorf("unknown storage: %q", storageURL)
	}
}
