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

package config

import (
	"github.com/kelseyhightower/envconfig"
	"github.com/pkg/errors"
)

// Config holds configuration from the env variables
type Config struct {
	Cloud                    string `envconfig:"AZURE_ENVIRONMENT" default:"AzurePublicCloud"`
	TenantID                 string `envconfig:"AZURE_TENANT_ID"`
	SpiffeHelperSidecarImage string `envconfig:"SPIFFE_HELPER_SIDECAR_IMAGE" default:"federid/spiffe-helper:latest"`
}

// ParseConfig parses the configuration from env variables
func ParseConfig() (*Config, error) {
	c := new(Config)
	if err := envconfig.Process("config", c); err != nil {
		return c, err
	}

	// validate parsed config
	if err := validateConfig(c); err != nil {
		return nil, err
	}
	return c, nil
}

// validateConfig validates the configuration
func validateConfig(c *Config) error {
	if c.SpiffeHelperSidecarImage == "" {
		return errors.New("SPIFFE_HELPER_SIDECAR_IMAGE is required")
	}
	return nil
}
