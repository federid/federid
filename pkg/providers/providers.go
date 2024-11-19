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
*/

package providers

import (
	corev1 "k8s.io/api/core/v1"
)

// ProviderConfig is a placeholder interface for provider configuration.
type ProviderConfig interface{}

// IdentityProvider defines methods for different identity providers.
type IdentityProvider interface {
	// ParseAnnotations parses annotations to configure the identity provider.
	ParseAnnotations(annotations map[string]string) IdentityProvider

	// AddEnvironmentVariables adds necessary environment variables to the container.
	AddEnvironmentVariables(container *corev1.Container) *corev1.Container

	// AddTokenFile adds a token file to the provider.
	AddTokenFile(tokenFile string)
}

// GetProviders initializes and returns a list of identity providers based on annotations.
// It checks if a provider is enabled in the annotations and appends it to the list.
func GetProviders(annotations map[string]string) []IdentityProvider {
	var providers []IdentityProvider

	// Check for Azure provider annotation and initialize it if enabled
	if annotations[AzureProviderEnableAnnotation] == "true" {
		azureProvider := &AzureProvider{}
		azureProvider.ParseAnnotations(annotations)
		providers = append(providers, azureProvider)
	}

	// Check for AWS provider annotation and initialize it if enabled
	if annotations[AWSProviderEnableAnnotation] == "true" {
		awsProvider := &AWSProvider{}
		awsProvider.ParseAnnotations(annotations)
		providers = append(providers, awsProvider)
	}

	// Check for GCP provider annotation and initialize it if enabled
	if annotations[GCPProviderEnableAnnotation] == "true" {
		gcpProvider := &GCPProvider{}
		gcpProvider.ParseAnnotations(annotations)
		providers = append(providers, gcpProvider)
	}

	// Additional provider checks can be added here as needed.

	return providers
}

/*
	AZURE
*/

// AzureConfig holds the configuration for the Azure identity provider.
type AzureConfig struct {
	Audience      string // JWT audience for Azure
	ClientID      string // Azure Client ID
	TenantID      string // Azure Tenant ID
	AuthorityHost string // Authority host URL for Azure
	TokenFile     string // Path to the token file
}

// AzureProvider implements the IdentityProvider interface for Azure.
type AzureProvider struct {
	Config AzureConfig // Holds the configuration for the Azure identity provider
}

// ParseAnnotations parses annotations to populate the AzureConfig structure.
func (a *AzureProvider) ParseAnnotations(annotations map[string]string) IdentityProvider {
	// Populate the AzureConfig with values from annotations
	a.Config = AzureConfig{
		Audience:      annotations[AzureJWTAudience],             // JWT audience for Azure
		ClientID:      annotations[AzureClientIDAnnotation],      // Azure Client ID
		TenantID:      annotations[AzureTenantIDAnnotation],      // Azure Tenant ID
		AuthorityHost: annotations[AzureAuthorityHostAnnotation], // Authority host URL for Azure
	}

	return a // Return the provider itself
}

// AddTokenFile sets the token file location for the Azure provider.
func (a *AzureProvider) AddTokenFile(tokenFile string) {
	a.Config.TokenFile = tokenFile // Store the provided token file path
}

// AddEnvironmentVariables adds necessary environment variables to the container for Azure provider configuration.
func (a *AzureProvider) AddEnvironmentVariables(container *corev1.Container) *corev1.Container {

	// Create a map to check if environment variables are already set in the container
	m := make(map[string]string)
	for _, env := range container.Env {
		m[env.Name] = env.Value
	}

	// Add the Azure Client ID environment variable if not already set
	if _, ok := m[AzureClientIDEnvVar]; !ok {
		clientID := a.Config.ClientID
		container.Env = append(container.Env, corev1.EnvVar{Name: AzureClientIDEnvVar, Value: clientID})
	}

	// Add the Azure Tenant ID environment variable if not already set
	if _, ok := m[AzureTenantIDEnvVar]; !ok {
		tenantID := a.Config.TenantID
		container.Env = append(container.Env, corev1.EnvVar{Name: AzureTenantIDEnvVar, Value: tenantID})
	}

	// Add the Azure Authority Host environment variable if not already set
	if _, ok := m[AzureAuthorityHostEnvVar]; !ok {
		azureAuthorityHost := a.Config.AuthorityHost
		if azureAuthorityHost == "" {
			// Set default value if the authority host is not provided
			azureAuthorityHost = AzureAuthorityHostEnvVarDefault
		}
		container.Env = append(container.Env, corev1.EnvVar{Name: AzureAuthorityHostEnvVar, Value: azureAuthorityHost})
	}

	// Add the Azure Federated Token File environment variable if not already set
	if _, ok := m[AzureFederatedTokenFileEnvVar]; !ok {
		tokenFile := a.Config.TokenFile
		container.Env = append(container.Env, corev1.EnvVar{Name: AzureFederatedTokenFileEnvVar, Value: tokenFile})
	}

	// Return the modified container with the added environment variables
	return container
}

/*
	AWS
*/

// AWSConfig contains the configuration for the AWS provider.
type AWSConfig struct {
	RoleARN   string // The AWS Role ARN to assume for authentication
	TokenFile string // Path to the AWS federated token file (if any)
}

// AWSProvider implements IdentityProvider for AWS.
type AWSProvider struct {
	Config AWSConfig // Holds the AWS provider's configuration
}

// ParseAnnotations parses annotations from the provided map and configures the AWS provider.
func (a *AWSProvider) ParseAnnotations(annotations map[string]string) IdentityProvider {
	// Initialize the AWSConfig with RoleARN from annotations
	a.Config = AWSConfig{
		RoleARN: annotations[AWSProviderRoleARNAnnotation], // Extract Role ARN for AWS provider
	}

	// Return the AWSProvider instance
	return a
}

// AddTokenFile sets the federated token file path for the AWS provider.
func (a *AWSProvider) AddTokenFile(tokenFile string) {
	a.Config.TokenFile = tokenFile // Assign the token file path to the provider's config
}

// AddEnvironmentVariables adds necessary environment variables for the AWS provider to the given container.
func (a *AWSProvider) AddEnvironmentVariables(container *corev1.Container) *corev1.Container {

	// Get the Role ARN and Token File from the provider's configuration
	roleARN := a.Config.RoleARN
	tokenFile := a.Config.TokenFile

	// Create a map to track existing environment variables in the container
	m := make(map[string]string)
	for _, env := range container.Env {
		m[env.Name] = env.Value
	}

	// Add the AWS Role ARN environment variable if not already set
	if _, ok := m[AWSRoleARNEvVar]; !ok {
		container.Env = append(container.Env, corev1.EnvVar{Name: AWSRoleARNEvVar, Value: roleARN})
	}

	// Add the token file environment variable if not already set
	if _, ok := m[AWSFIdentityTokenFileEnvVar]; !ok {
		container.Env = append(container.Env, corev1.EnvVar{Name: AWSFIdentityTokenFileEnvVar, Value: tokenFile})
	}

	// Return the updated container with the environment variables
	return container
}

/*
	GCP
*/

// GCPConfig holds the configuration needed for the GCP identity provider.
type GCPConfig struct {
	Audience       string // The audience for the GCP identity provider
	ServiceAccount string // The service account to use with GCP
	TokenFile      string // The path to the token file
}

// GCPProvider represents the GCP identity provider and holds the configuration.
type GCPProvider struct {
	Config GCPConfig
}

// ParseAnnotations parses the annotations from the provided map and sets the relevant values
// in the GCPProvider's configuration. This is typically used to initialize the provider
// with the information from the Kubernetes Pod annotations.
func (a *GCPProvider) ParseAnnotations(annotations map[string]string) IdentityProvider {
	// Set the configuration for the GCP provider using the provided annotations
	a.Config = GCPConfig{
		Audience:       annotations[GCPAudienceAnnotation],       // Set the Audience from annotations
		ServiceAccount: annotations[GCPServiceAccountAnnotation], // Set the Service Account from annotations
	}

	return a // Return the provider itself for further chaining if necessary
}

// AddTokenFile sets the token file path in the GCPProvider's configuration.
func (a *GCPProvider) AddTokenFile(tokenFile string) {
	a.Config.TokenFile = tokenFile
}

// AddEnvironmentVariables adds necessary environment variables for the GCP provider to the given container.
// This ensures that the container has the required configuration for GCP integration.
func (a *GCPProvider) AddEnvironmentVariables(container *corev1.Container) *corev1.Container {

	// Extract configuration values
	audience := a.Config.Audience
	serviceAccount := a.Config.ServiceAccount
	tokenFile := a.Config.TokenFile

	// Map to check if the environment variable already exists in the container
	m := make(map[string]string)
	for _, env := range container.Env {
		m[env.Name] = env.Value
	}

	// Add the audience env var if not already set
	if _, ok := m[GCPAudienceEnvVar]; !ok {
		container.Env = append(container.Env, corev1.EnvVar{Name: GCPAudienceEnvVar, Value: audience})
	}

	// Add the service account env var if not already set
	if _, ok := m[GCPServiceAccountEnvVar]; !ok {
		container.Env = append(container.Env, corev1.EnvVar{Name: GCPServiceAccountEnvVar, Value: serviceAccount})
	}

	// Add the token file env var if not already set
	if _, ok := m[GCPTokenFile]; !ok {
		container.Env = append(container.Env, corev1.EnvVar{Name: GCPTokenFile, Value: tokenFile})
	}

	return container
}
