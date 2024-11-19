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
package webhook

// Constants related to annotations and labels defined for service accounts.
const (
	// UseWorkloadIdentityLabel indicates that the service account is configured to use workload identity.
	UseWorkloadIdentityLabel = "federid.io/use"

	// SkipContainersAnnotation specifies a list of container names that should skip adding the projected
	// service account token volume. If the service account has the `federid.io/use` label, the token volume
	// is added to all containers by default, unless excluded via this annotation.
	SkipContainersAnnotation = "federid.io/skip-containers"

	// JWTAudienceAnnotation specifies the audience for the projected service account token.
	JWTAudienceAnnotation = "federid.io/audience"

	// JWTExtraAudiencesAnnotation specifies additional audiences for the projected service account token.
	JWTExtraAudiencesAnnotation = "federid.io/extra-audiences"

	// JWTAudienceDefault is the default audience for the projected service account token.
	JWTAudienceDefault = "federid"

	// JWTIssuerDefault is the default issuer for the projected service account token.
	JWTIssuerDefault = string(SPIFFE)

	// JWTIssuerAnnotation specifies the issuer for the projected service account token.
	JWTIssuerAnnotation = "federid.io/issuer"

	// JWTExpirationAnnotation specifies the expiration time (in seconds) for the projected service account token.
	// This field is optional. Configuring it can help avoid downtime caused by token refresh errors.
	JWTExpirationAnnotation = "federid.io/jwt-expiration"

	// JWTExpirationDefault is the default expiration time (in seconds) for the projected service account token.
	// This value aligns with Kubernetes' default for projected service account tokens.
	JWTExpirationDefault = int64(3600)

	// JWTExpirationMin is the minimum allowed expiration time (in seconds) for the projected service account token.
	JWTExpirationMin = int64(3600)

	// JWTExpirationMax is the maximum allowed expiration time (in seconds) for the projected service account token.
	JWTExpirationMax = int64(86400)

	// JWTVolumeName is the name of the volume used for mounting the projected service account token.
	JWTVolumeName = "federid-token"

	// JWTVolumeMount is the mount path of the projected service account token volume within the container.
	JWTVolumeMount = "/run/secrets/federid.io"

	// JWTFileName is the name of the file containing the projected service account token.
	JWTFileName = "token"

	// JWTFilePath is the full path to the projected service account token file.
	JWTFilePath = JWTVolumeMount + "/" + JWTFileName
)

// Issuer defines the type of JWT issuer.
type Issuer string

const (
	// SPIFFE represents the SPIFFE (Secure Production Identity Framework for Everyone) issuer.
	SPIFFE Issuer = "spiffe"

	// Kubernetes represents the Kubernetes issuer.
	Kubernetes Issuer = "kubernetes"
)

// Constants related to the SPIFFE helper environment variables injected into the pod.
const (
	// SpiffeHelperSidecarContainerName is the name of the sidecar container running the SPIFFE helper.
	SpiffeHelperSidecarContainerName = "federid-spiffe-helper"

	// SpiffeHelperSidecarContainerWorkloadAPIVolumeName is the name of the volume used for the SPIFFE workload API socket.
	SpiffeHelperSidecarContainerWorkloadAPIVolumeName = "spiffe-workload-api"

	// SpiffeHelperSidecarContainerWorkloadAPIVolumeMount is the mount path for the SPIFFE workload API socket.
	SpiffeHelperSidecarContainerWorkloadAPIVolumeMount = "/spiffe-workload-api"

	// SpiffeHelperSidecarContainerConfigVolumeName is the name of the volume for the SPIFFE helper configuration.
	SpiffeHelperSidecarContainerConfigVolumeName = "spiffe-helper-config"

	// SpiffeHelperSidecarContainerConfigVolumeMount is the mount path for the SPIFFE helper configuration files.
	SpiffeHelperSidecarContainerConfigVolumeMount = "/opt/spiffe-helper"

	// SpiffeHelperAgentAddressEnvVar is the environment variable for the SPIFFE agent's address.
	SpiffeHelperAgentAddressEnvVar = "AGENT_ADDRESS"

	// SpiffeHelperAgentAddressDefault is the default address of the SPIFFE agent's socket.
	SpiffeHelperAgentAddressDefault = "/spiffe-workload-api/spire-agent.sock"

	// SpiffeHelperDaemonModeEnvVar is the environment variable indicating whether the SPIFFE helper runs in daemon mode.
	SpiffeHelperDaemonModeEnvVar = "DAEMON_MODE"

	// SpiffeHelperDaemonModeDefault is the default value for running the SPIFFE helper in daemon mode.
	SpiffeHelperDaemonModeDefault = "true"

	// SpiffeHelperJWTAudienceEnvVar is the environment variable for the audience of JWT-SVIDs.
	SpiffeHelperJWTAudienceEnvVar = "JWT_SVIDS_JWT_AUDIENCE"

	// SpiffeHelperJWTExtraAudiencesEnvVar is the environment variable for specifying additional audiences for JWT-SVIDs.
	SpiffeHelperJWTExtraAudiencesEnvVar = "JWT_SVIDS_JWT_EXTRA_AUDIENCES"

	// SpiffeHelperJWTExtraAudiencesDefault is the default value for additional audiences for JWT-SVIDs.
	SpiffeHelperJWTExtraAudiencesDefault = "[]"

	// SpiffeHelperJWTFileName is the environment variable for the file name of the JWT-SVID.
	SpiffeHelperJWTFileName = "JWT_SVIDS_JWT_SVID_FILE_NAME"

	// SpiffeHelperJWTFileNameDefault is the default file name for the JWT-SVID.
	SpiffeHelperJWTFileNameDefault = JWTFilePath

	// SpiffeHelperJWTFileMode is the environment variable for the file permissions of the JWT-SVID.
	SpiffeHelperJWTFileMode = "JWT_SVID_FILE_MODE"

	// SpiffeHelperJWTFileModeDefault is the default file mode for the JWT-SVID.
	SpiffeHelperJWTFileModeDefault = "0440"

	// SpiffeHelperJWTBundleFile is the environment variable for the file name of the JWT-SVID bundle.
	SpiffeHelperJWTBundleFile = "JWT_BUNDLE_FILE_NAME"

	// SpiffeHelperJWTBundleFileDefault is the default file name for the JWT-SVID bundle.
	SpiffeHelperJWTBundleFileDefault = JWTVolumeMount + "/" + "bundle.json"

	// SpiffeHelperJWTBundleMode is the environment variable for the file permissions of the JWT-SVID bundle.
	SpiffeHelperJWTBundleMode = "JWT_BUNDLE_FILE_MODE"

	// SpiffeHelperJWTBundleModeDefault is the default file mode for the JWT-SVID bundle.
	SpiffeHelperJWTBundleModeDefault = "0444"
)
