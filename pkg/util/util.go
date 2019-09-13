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

package util

import "fmt"

// useful for particular case i'm interested in where elements should not repeat
func UniqueStringSliceCmp(src []string, dst []string) (err error) {
	if len(src) != len(dst) {
		return fmt.Errorf("different length")
	}
	cmpMap := make(map[string]int)
	for idx := 0; idx < len(src); idx++ {
		var ok bool
		_, ok = cmpMap[src[idx]]
		if !ok {
			cmpMap[src[idx]] = 1
		}
		_, ok = cmpMap[dst[idx]]
		if !ok {
			cmpMap[dst[idx]] = 1
		}

		// exit early if we find differences
		if len(cmpMap) > len(src) {
			return fmt.Errorf("different (or repeating) elements")
		}
	}
	if len(cmpMap) != len(src) {
		return fmt.Errorf("different (or repeating) elements")
	}

	return nil
}
