# Federid - Federated Workload Identity for Kubernetes
Federid enables seamless integration of identity providers (Azure, AWS, and GCP) with Kubernetes workloads, supporting two mechanisms for workload authentication: Kubernetes Service Account Tokens or SPIFFE/SPIRE Tokens. Federid allows Kubernetes pods to authenticate and retrieve identity tokens through service account tokens or injected environment variables, streamlining secure interactions with cloud-native services.

This project is part of the Master Thesis [**Kubernetes Workload Identity Federation**](https://openaccess.uoc.edu/handle/10609/152143)  
by **Emiliano Spinella**, *Universitat Oberta de Catalunya*.

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

## Enable FederID in Pods

To enable FederID features such as JWT token injection and environment variable configuration, you need to label the relevant pods with `federid.io/use: "true"`. 

This label signals the federid webhook to process the pod and inject the necessary resources.

### Example: Labeling a Pod in a Deployment
Below is an example of a Kubernetes Deployment with the required label applied:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: federid-test
  namespace: default
  labels:
    app: federid-test
spec:
  selector:
    matchLabels:
      app: federid-test
  template:
    metadata:
      labels:
        app: federid-test
        federid.io/use: "true" # Label required to enable FederID
    spec:
      serviceAccountName: federid-aws # Ensure this account has appropriate permissions
      containers:
        - name: client
          image: federid/tester:latest
          command: ["sleep"]
          args: ["1000000000"]
```


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

Environment variables that will be injected into all containers of the Pod:
- `AWS_ROLE` = `arn:aws:iam::111111111111:role/MyFederidRole` 
- `AWS_WEB_IDENTITY_TOKEN_FILE` = JWT file path injected by Federid (defaults to: `/run/secrets/federid.io/token`)

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

Environment variables that will be injected into all containers of the Pod:
- `AWS_ROLE` = `arn:aws:iam::111111111111:role/MyFederidRole`
- `AWS_WEB_IDENTITY_TOKEN_FILE` = JWT file path injected by Federid (defaults to: `/run/secrets/federid.io/token`)

#### Test AWS authentication

AWS automatically detects the injected environment variables as part of its SDK. Therefore, it is not necessary to login. 

If the `AWS_ROLE` has S3 list permissions, you can try:

```bash
aws s3 ls
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

Environment variables that will be injected into all containers of the Pod:
- `AZURE_TENANT_ID` = `ffffffff-acaf-40f9-b944-aaaaaaaaaaaa`
- `AZURE_CLIENT_ID` = `ffffffff-8f34-46a7-b80e-aaaaaaaaaaaa`
- `AZURE_AUTHORITY_HOST` = `https://login.microsoftonline.com`
- `AZURE_FEDERATED_TOKEN_FILE` = JWT file path injected by Federid (defaults to: `/run/secrets/federid.io/token`)

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

Environment variables that will be injected into all containers of the Pod:
- `AZURE_TENANT_ID` = `ffffffff-acaf-40f9-b944-aaaaaaaaaaaa`
- `AZURE_CLIENT_ID` = `ffffffff-8f34-46a7-b80e-aaaaaaaaaaaa`
- `AZURE_AUTHORITY_HOST` = `https://login.microsoftonline.com`
- `AZURE_FEDERATED_TOKEN_FILE` = JWT file path injected by Federid (defaults to: `/run/secrets/federid.io/token`)

#### Test Azure authentication

```bash
az login --federated-token "$(cat $AZURE_FEDERATED_TOKEN_FILE)" --service-principal -u $AZURE_CLIENT_ID -t $AZURE_TENANT_ID
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

Environment variables that will be injected into all containers of the Pod:
- `AZURE_TENANT_ID` = `ffffffff-acaf-40f9-b944-aaaaaaaaaaaa`
- `AZURE_CLIENT_ID` = `ffffffff-8f34-46a7-b80e-aaaaaaaaaaaa`
- `AZURE_AUTHORITY_HOST` = `https://login.microsoftonline.com`
- `AZURE_FEDERATED_TOKEN_FILE` = JWT file path injected by Federid (defaults to: `/run/secrets/federid.io/token`)


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

Environment variables that will be injected into all containers of the Pod:
- `FEDERID_GCP_SERVICE_ACCOUNT` = `sa@project.iam.gserviceaccount.com`
- `FEDERID_GCP_AUDIENCE` = `projects/111111111111/locations/global/workloadIdentityPools/idp-com/providers/sts-idp-com`
- `FEDERID_GCP_TOKEN` = JWT file path injected by Federid (defaults to: `/run/secrets/federid.io/token`)

In the case of GCP, injected environment variables do not belong to the Google SDK.

#### Test GCP authentication

```bash
export GOOGLE_APPLICATION_CREDENTIALS=/tmp/gcp_sa.json

gcloud iam workload-identity-pools create-cred-config $FEDERID_GCP_AUDIENCE \
--service-account=$FEDERID_GCP_SERVICE_ACCOUNT \
--credential-source-file=$FEDERID_GCP_TOKEN \
--credential-source-type=text \
--output-file=$GOOGLE_APPLICATION_CREDENTIALS

gcloud auth login --cred-file=$GOOGLE_APPLICATION_CREDENTIALS
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

