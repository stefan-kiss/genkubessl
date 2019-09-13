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

package kubeconfigs

import "github.com/stefan-kiss/genkubessl/pkg/storage"

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
)

type KubeConfigTemplate struct {
	path     string
	parentCA string
	parrent  string
	nodes    []string
}

type KubeConfig struct {
	configTXT    string
	node         string
	templateIdx  int
	readStorage  storage.StoreDrv
	writeStorage storage.StoreDrv
	failed       string
}
