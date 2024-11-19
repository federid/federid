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

// Azure-specific constants and environment variables for workload identity
const (
	// AzureProviderEnableAnnotation indicates whether the Azure provider is enabled for workload identity.
	AzureProviderEnableAnnotation = "azure.federid.io/use"

	// AzureClientIDAnnotation specifies the client ID to be used by the pod.
	AzureClientIDAnnotation = "azure.federid.io/client-id"

	// AzureTenantIDAnnotation specifies the tenant ID to be used by the pod.
	AzureTenantIDAnnotation = "azure.federid.io/tenant-id"

	// SkipContainersAnnotation specifies a list of container names that should skip adding the projected
	// service account token volume. If the service account is labeled with `azure.federid.io/use: true`,
	// the token volume is added to all containers by default unless excluded via this annotation.
	SkipContainersAnnotation = "federid.io/skip-containers"

	// AzureAuthorityHostAnnotation specifies the authority host URL for Azure.
	AzureAuthorityHostAnnotation = "azure.federid.io/authority-host"

	// AzureJWTAudience specifies the audience for the projected service account token in Azure.
	AzureJWTAudience = "azure.federid.io/audience"
)

// Azure environment variables injected into the pod
const (
	// AzureClientIDEnvVar specifies the environment variable for the Azure client ID.
	AzureClientIDEnvVar = "AZURE_CLIENT_ID"

	// AzureTenantIDEnvVar specifies the environment variable for the Azure tenant ID.
	AzureTenantIDEnvVar = "AZURE_TENANT_ID"

	// AzureFederatedTokenFileEnvVar specifies the environment variable for the path to the federated token file.
	// #nosec is used to bypass security scanning for this hardcoded value.
	AzureFederatedTokenFileEnvVar = "AZURE_FEDERATED_TOKEN_FILE" // #nosec

	// AzureAuthorityHostEnvVar specifies the environment variable for the Azure authority host URL.
	AzureAuthorityHostEnvVar = "AZURE_AUTHORITY_HOST"

	// AzureAuthorityHostEnvVarDefault specifies the default authority host URL for Azure.
	AzureAuthorityHostEnvVarDefault = "https://login.microsoftonline.com"
)

// AWS-specific constants and environment variables for workload identity
const (
	// AWSProviderEnableAnnotation indicates whether the AWS provider is enabled for workload identity.
	AWSProviderEnableAnnotation = "aws.federid.io/use"

	// AWSProviderRoleARNAnnotation specifies the Amazon Resource Name (ARN) of the role to be assumed.
	AWSProviderRoleARNAnnotation = "aws.federid.io/role-arn"
)

// AWS environment variables injected into the pod
const (
	// AWSRoleARNEvVar specifies the environment variable for the AWS role ARN.
	AWSRoleARNEvVar = "AWS_ROLE_ARN"

	// AWSFIdentityTokenFileEnvVar specifies the environment variable for the path to the web identity token file.
	AWSFIdentityTokenFileEnvVar = "AWS_WEB_IDENTITY_TOKEN_FILE"
)

// GCP-specific constants and environment variables for workload identity
const (
	// GCPProviderEnableAnnotation indicates whether the GCP provider is enabled for workload identity.
	GCPProviderEnableAnnotation = "gcp.federid.io/use"

	// GCPServiceAccountAnnotation specifies the GCP service account to be used by the workload.
	GCPServiceAccountAnnotation = "gcp.federid.io/service-account"

	// GCPAudienceAnnotation specifies the audience for the projected service account token in GCP.
	GCPAudienceAnnotation = "gcp.federid.io/audience"
)

// GCP environment variables injected into the pod
const (
	// GCPServiceAccountEnvVar specifies the environment variable for the GCP service account email.
	GCPServiceAccountEnvVar = "FEDERID_GCP_SERVICE_ACCOUNT"

	// GCPAudienceEnvVar specifies the environment variable for the audience in GCP.
	GCPAudienceEnvVar = "FEDERID_GCP_AUDIENCE"

	// GCPTokenFile specifies the environment variable for the path to the GCP token file.
	GCPTokenFile = "FEDERID_GCP_TOKEN"

	// GCPApplicationCredentialsEnvVar specifies the environment variable for the path to the GCP application credentials.
	GCPApplicationCredentialsEnvVar = "GOOGLE_APPLICATION_CREDENTIALS"

	// GCPConfigFileEnvVar specifies the environment variable for the path to the GCP configuration file.
	GCPConfigFileEnvVar = "CLOUDSDK_CONFIG"

	// GCPProjectEnvVar specifies the environment variable for the GCP project configuration.
	GCPProjectEnvVar = "CLOUDSDK_CORE_PROJECT"
)
