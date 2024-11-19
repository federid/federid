# Federid - Federated Workload Identity for Kubernetes
Federid enables seamless integration of identity providers (Azure, AWS, and GCP) with Kubernetes workloads, supporting two mechanisms for workload authentication: Kubernetes Service Account Tokens or SPIFFE/SPIRE Tokens. Federid allows Kubernetes pods to authenticate and retrieve identity tokens through service account tokens or injected environment variables, streamlining secure interactions with cloud-native services.

## Features
- Service Account Tokens: Automatically injects Kubernetes service account tokens into pods for seamless authentication.
- SPIFFE/SPIRE Tokens: Option to authenticate via SPIFFE tokens using SPIFFE/SPIRE for secure identity federation.
- Identity Provider Integration: Supports Azure, AWS, and GCP identity providers.
- Sidecar Injection: Integrates a Spiffe Helper sidecar container for managing tokens and identity federation with SPIFFE.
- Environment Variable Injection: Automatically injects the required environment variables for each cloud identity provider.
- Flexible Configuration: Supports multiple authentication mechanisms (Service Account Tokens or SPIFFE/SPIRE) via Kubernetes annotations.

## Architecture Overview
Federid facilitates identity federation between Kubernetes workloads and cloud identity providers by employing the following mechanisms:

- Service Account Token Projection: Federid ensures Kubernetes service account tokens are projected as volumes within pods, making identity tokens available for authentication.
- SPIFFE Integration: SPIFFE/SPIRE tokens are supported as an alternative authentication method, providing a secure identity federation model for workloads.
- Sidecar Injection: A spiffe-helper sidecar container is injected into the pod, ensuring secure communication with the SPIFFE API for token management.
- Cloud Provider Integration: The solution integrates with Azure, AWS, and GCP for identity management and secure authentication across cloud environments.

## Authentication Mechanisms
Federid allows users to choose between two authentication mechanisms for Kubernetes workloads:

1. Kubernetes Service Account Token
This mechanism uses the Kubernetes native service account tokens, injected as environment variables into the pod. It is the default choice for most Kubernetes workloads.

2. SPIFFE/SPIRE Token
This mechanism allows workloads to authenticate using SPIFFE/SPIRE tokens, leveraging a sidecar container (spiffe-helper) to manage identity federation.

## Installing Federid
To deploy Federid in your Kubernetes cluster, follow these steps:

### Prerequisites
- A Kubernetes cluster (version 1.18 or newer).
- kubectl configured to interact with your Kubernetes cluster.
- Proper IAM permissions and access for integrating with AWS, Azure, or GCP (depending on your authentication provider).

### Steps to Install Federid
#### Helm Chart
The Helm charts for deploying federid are available in a separate repository. They provide an easy way to deploy and manage the application in Kubernetes.

👉 [Helm Charts Repository](https://github.com/federid/helm-charts)

#### Apply the Federid Manifest

To deploy Federid, apply the manifest located in the deploy/federid.yaml file:

```bash
kubectl apply -f deploy/federid.yaml
```

This will:
- Create a new namespace called federid.
- Deploy necessary resources, including ServiceAccount, Role, ClusterRole, Secret, Deployment, and MutatingWebhookConfiguration.

#### Verify the Deployment

After applying the manifest, verify that the federid components are deployed correctly:
```bash
kubectl get pods -n federid
```

You should see the federid-webhook pod running.

## Service Account Annotations
Federid uses Kubernetes annotations to define which authentication mechanism to use for a given ServiceAccount. Users can annotate their ServiceAccount to either use Kubernetes Service Account Tokens or SPIFFE/SPIRE Tokens.

### AWS Examples
#### Service Account with SPIFFE/SPIRE Token
```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: federid-aws
  namespace: default
  annotations:
    federid.io/audience: 'federid'  # Optional, defaults to 'federid'
    aws.federid.io/use: 'true'  # Enable AWS provider
    aws.federid.io/role-arn: 'arn:aws:iam::111111111111:role/MyFederidRole'  # Required
```

#### Service Account with Kubernetes Service Account Token
```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: federid-aws
  namespace: default
  annotations:
    federid.io/audience: 'federid'  # Optional, defaults to 'federid'
    federid.io/issuer: 'kubernetes'  # Optional, defaults to 'spiffe'
    aws.federid.io/use: 'true'  # Enable AWS provider
    aws.federid.io/role-arn: 'arn:aws:iam::111111111111:role/MyFederidRole'  # Required
```
### Azure Examples
#### Service Account with SPIFFE/SPIRE Token
```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: federid-azure
  namespace: default
  annotations:
    federid.io/audience: 'federid'  # Required
    azure.federid.io/use: 'true'  # Enable Azure provider
    azure.federid.io/authority-host: 'https://login.microsoftonline.com'  # Optional
    azure.federid.io/tenant-id: 'ffffffff-acaf-40f9-b944-aaaaaaaaaaaa'  # Required
    azure.federid.io/client-id: 'ffffffff-8f34-46a7-b80e-aaaaaaaaaaaa'  # Required
```

#### Service Account with Kubernetes Service Account Token
```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: federid-azure
  namespace: default
  annotations:
    federid.io/audience: 'federid'  # Required
    federid.io/issuer: 'kubernetes'  # Optional, defaults to 'spiffe'
    azure.federid.io/use: 'true'  # Enable Azure provider
    azure.federid.io/authority-host: 'https://login.microsoftonline.com'  # Optional
    azure.federid.io/tenant-id: 'ffffffff-acaf-40f9-b944-aaaaaaaaaaaa'  # Required
    azure.federid.io/client-id: 'ffffffff-8f34-46a7-b80e-aaaaaaaaaaaa'  # Required
```

### GCP Examples
#### Service Account with SPIFFE/SPIRE Token
```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: federid-gcp
  namespace: default
  annotations:
    federid.io/audience: 'federid'  # Optional, defaults to 'federid'
    gcp.federid.io/use: 'true'  # Enable GCP provider
    gcp.federid.io/service-account: 'sa@project.iam.gserviceaccount.com'  # Required
    gcp.federid.io/audience: 'projects/111111111111/locations/global/workloadIdentityPools/idp-com/providers/sts-idp-com'  # Required
```
#### Service Account with Kubernetes Service Account Token
```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: federid-gcp
  namespace: default
  annotations:
    federid.io/audience: 'federid'  # Optional, defaults to 'federid'
    federid.io/issuer: 'kubernetes'  # Optional, defaults to 'spiffe'
    gcp.federid.io/use: 'true'  # Enable GCP provider
    gcp.federid.io/service-account: 'sa@project.iam.gserviceaccount.com'  # Required
    gcp.federid.io/audience: 'projects/111111111111/locations/global/workloadIdentityPools/idp-com/providers/sts-idp-com'  # Required
```

## Requirements
Kubernetes (version 1.12+)
Cloud environment credentials for Azure, AWS, or GCP (depending on the identity provider you wish to use).
Configurable annotations in Kubernetes pods to enable identity provider integration.

## Contributing
Feel free to fork the repository and submit issues or pull requests for bug fixes or improvements.

## Licensing

This project is licensed under the Apache License, Version 2.0.

Parts of this project are based on [azure-workload-identity](https://github.com/Azure/azure-workload-identity), which is licensed under the MIT License. See the `LICENSE` file for details.

