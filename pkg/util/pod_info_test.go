/*
Copyright 2014 The Federid Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
***
This file contains code derived from the project https://github.com/Azure/azure-workload-identity
The original code is licensed under the MIT License.
See the LICENSE file for more information.
*/

package util

import (
	"os"
	"testing"
)

func TestGetNamespace(t *testing.T) {
	tests := []struct {
		name         string
		podNamespace string
		want         string
	}{
		{
			name:         "default webhook namespace",
			podNamespace: "",
			want:         "federid",
		},
		{
			name:         "namespace set",
			podNamespace: "kube-system",
			want:         "kube-system",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.podNamespace != "" {
				os.Setenv("POD_NAMESPACE", tt.podNamespace)
				defer os.Unsetenv("POD_NAMESPACE")
			}

			if got := GetNamespace(); got != tt.want {
				t.Errorf("GetNamespace() = %v, want %v", got, tt.want)
			}
		})
	}
}
