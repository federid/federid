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

package prometheus

import (
	crprometheus "github.com/prometheus/client_golang/prometheus"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/prometheus"
	"go.opentelemetry.io/otel/sdk/metric"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
)

const (
	// ExporterName is the name of the exporter
	ExporterName = "prometheus"
)

func InitExporter() error {
	exporter, err := prometheus.New(
		prometheus.WithRegisterer(metrics.Registry.(*crprometheus.Registry)),
	)
	if err != nil {
		return err
	}

	meterProvider := metric.NewMeterProvider(
		metric.WithReader(exporter),
		metric.WithView(metric.NewView(
			metric.Instrument{Name: "azwi_*"},
			metric.Stream{
				Aggregation: metric.AggregationExplicitBucketHistogram{
					Boundaries: []float64{0.001, 0.002, 0.003, 0.004, 0.005, 0.006, 0.007, 0.008, 0.009, 0.01, 0.02, 0.03, 0.04, 0.05, 0.06, 0.07, 0.08, 0.09, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1, 1.5, 2, 2.5, 3},
				}},
		)),
	)

	otel.SetMeterProvider(meterProvider)

	return nil
}
