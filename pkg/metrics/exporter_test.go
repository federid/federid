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

package metrics

import "testing"

func TestInitMetricsExporter(t *testing.T) {
	tests := []struct {
		name           string
		metricsBackend string
	}{
		{
			name:           "prometheus",
			metricsBackend: "prometheus",
		},
		{
			name:           "Prometheus",
			metricsBackend: "Prometheus",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := InitMetricsExporter(tt.metricsBackend); err != nil {
				t.Errorf("InitMetricsExporter() error = %v, expected nil", err)
			}
		})
	}
}

func TestInitMetricsExporterError(t *testing.T) {
	if err := InitMetricsExporter("unknown"); err == nil {
		t.Errorf("InitMetricsExporter() error = nil, expected error")
	}
}
