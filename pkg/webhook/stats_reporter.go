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

package webhook

import (
	"context"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

const (
	requestDurationMetricName = "federid_mutation_request"

	namespaceKey = "namespace"
)

var (
	req metric.Float64Histogram
	// if service.name is not specified, the default is "unknown_service:<exe name>"
	// xref: https://opentelemetry.io/docs/reference/specification/resource/semantic_conventions/#service
	labels = []attribute.KeyValue{attribute.String("service.name", "webhook")}
)

func registerMetrics() error {
	var err error
	meter := otel.Meter("webhook")

	req, err = meter.Float64Histogram(
		requestDurationMetricName,
		metric.WithDescription("Distribution of how long it took for the federid mutation request"))

	return err
}

// ReportRequest reports the request duration for the given namespace.
func ReportRequest(ctx context.Context, namespace string, duration time.Duration) {
	l := append(labels, attribute.String(namespaceKey, namespace))
	req.Record(ctx, duration.Seconds(), metric.WithAttributes(l...))
}
