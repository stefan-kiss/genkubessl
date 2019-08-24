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

import "testing"

var uniqStrA = []string{"1", "2", "3", "4", "5", "6"}
var uniqStrB = []string{"6", "5", "4", "3", "2", "1"}
var repeatStrA = []string{"1", "1", "2", "3", "4", "5", "6"}
var emptyStr = []string{}

var cert1Sans = []string{
	"kapi.example.org",
	"localhost",
	"master01.example.org",
	"kubernetes",
	"kubernetes.default",
	"kubernetes.default.svc",
	"kubernetes.default.svc.cluster.local",
	"10.0.0.1",
	"127.0.0.1",
	"1.1.1.1",
	"::1",
	"10.1.0.1",
	"10.1.0.2",
}

var cert2Sans = []string{
	"kapi.example.org",
	"10.0.0.1",
	"127.0.0.1",
	"1.1.1.1",
	"localhost",
	"::1",
	"master01.example.org",
	"10.1.0.1",
	"10.1.0.2",
	"kubernetes",
	"kubernetes.default",
	"kubernetes.default.svc",
	"kubernetes.default.svc.cluster.local",
}

func TestUniqueStringSliceCmp(t *testing.T) {
	var err error
	if err = UniqueStringSliceCmp(uniqStrA, uniqStrA); err != nil {
		t.Errorf("failed to compare same slice")
	}

	if err = UniqueStringSliceCmp(uniqStrA, uniqStrB); err != nil {
		t.Errorf("failed to compare same slice in different order")
	}

	if err = UniqueStringSliceCmp(uniqStrA, repeatStrA); err == nil {
		t.Errorf("failed to compare same slice with repeating elements")
	}

	if err = UniqueStringSliceCmp(uniqStrA, emptyStr); err == nil {
		t.Errorf("failed to compare same slice with repeating elements")
	}

	if err = UniqueStringSliceCmp(emptyStr, emptyStr); err != nil {
		t.Errorf("failed to compare same slice with repeating elements")
	}

	if err = UniqueStringSliceCmp(cert1Sans, cert2Sans); err != nil {
		t.Errorf("random order string slices with same elements")
	}

}
