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
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/federid/federid/pkg/config"
	"github.com/federid/federid/pkg/providers"
	"github.com/pkg/errors"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	"monis.app/mlog"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

// validIssuers is a map that defines the set of valid issuers.
// It is used to validate whether the issuer of a given workload is acceptable.
// The map keys are the Issuer types, and the values are boolean flags indicating if the issuer is enabled.
// TODO it should be possible to set this as ENV parameter
var validIssuers = map[Issuer]bool{
	SPIFFE:     true, // SPIFFE is a valid issuer.
	Kubernetes: true, // Kubernetes is a valid issuer.
}

// podMutator is a struct that represents a pod mutator in the webhook.
// It is responsible for modifying the pod object before it is persisted in the Kubernetes cluster.
// This mutation can include tasks like adding a project service account token volume or injecting a container into the pod.
type podMutator struct {
	client client.Client // client is an instance of the Kubernetes client used to interact with the cluster.
	// reader is an instance of mgr.GetAPIReader, which is a configured API reader used for reading resources from the cluster.
	// It is typically used when the standard client does not meet the use case, as it allows direct interaction with the API server.
	reader  client.Reader     // reader is used for low-level access to cluster resources, especially when the client cannot be used.
	config  *config.Config    // config holds the configuration settings, such as issuer types, loaded from the environment or file.
	decoder admission.Decoder // decoder is responsible for decoding incoming admission control requests into their appropriate representations.
}

// NewPodMutator creates and returns a new pod mutation handler.
// It initializes a podMutator with necessary configurations and resources
// such as the Kubernetes client, reader, and the runtime scheme for admission control.
func NewPodMutator(client client.Client, reader client.Reader, scheme *runtime.Scheme) (admission.Handler, error) {
	// Parse configuration settings from environment variables or default values.
	c, err := config.ParseConfig()
	if err != nil {
		return nil, err // Return an error if configuration parsing fails.
	}

	// Register metrics for monitoring. This might include metrics related to webhook events.
	if err := registerMetrics(); err != nil {
		return nil, errors.Wrap(err, "failed to register metrics") // Wrap and return error if metrics registration fails.
	}

	// Return a new podMutator instance, passing the necessary resources (client, reader, config, decoder).
	// This podMutator will handle pod mutations during admission control.
	return &podMutator{
		client:  client,                       // Kubernetes client used for interacting with the cluster.
		reader:  reader,                       // Reader for low-level access to Kubernetes resources.
		config:  c,                            // Configuration loaded from environment or defaults.
		decoder: admission.NewDecoder(scheme), // Decoder to handle admission control requests based on the runtime scheme.
	}, nil
}

// PodMutator adds projected service account volume for incoming pods if service account is annotated
func (m *podMutator) Handle(ctx context.Context, req admission.Request) (response admission.Response) {
	// Track the start time of the request to measure the duration of the operation
	timeStart := time.Now()

	// Ensure that we report the time taken for the request when the function completes (even if it returns early)
	defer func() {
		ReportRequest(ctx, req.Namespace, time.Since(timeStart)) // Report the duration of the request
	}()

	// Create an empty pod object to decode the incoming request into
	pod := &corev1.Pod{}

	// Decode the incoming admission request into the pod object
	// The decoder uses the request payload and converts it into a structured Pod object
	err := m.decoder.Decode(req, pod)
	if err != nil {
		// If there is an error decoding the request, return an error response
		return admission.Errored(http.StatusBadRequest, err)
	}

	// Print out the pod details for debugging purposes
	// %+v provides detailed information about the pod struct
	fmt.Printf("Pod details using fmt.Printf:\n%+v\n\n", pod)

	// Retrieve the name of the pod from the object metadata
	podName := pod.GetName()

	// If the pod does not have a name (it may be a generated name), use the generate name as a fallback
	if podName == "" {
		// Append "(prefix)" to indicate it’s a generated name
		podName = pod.GetGenerateName() + " (prefix)"
	}

	// Ensure the pod's namespace is set correctly. For daemonset or deployment pods,
	// the namespace may not be set in the object metadata, so we set it explicitly.
	pod.Namespace = req.Namespace

	// Retrieve the service account name associated with the pod
	serviceAccountName := pod.Spec.ServiceAccountName

	// When you create a pod, if you do not specify a service account, it is automatically
	// assigned the default service account in the same namespace.
	// The service account provides an identity for processes that run in the pod, allowing them
	// to access the Kubernetes API server and perform actions within the cluster.
	// For more information, refer to the official documentation:
	// https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/#use-the-default-service-account-to-access-the-api-server
	if serviceAccountName == "" {
		// If no service account is specified, assign the "default" service account
		// to ensure the pod can interact with the Kubernetes API server and other services.
		serviceAccountName = "default"
	}

	// Create a new logger instance for this handler to log relevant details.
	// The logger will include the pod name, namespace, and service account name in its context,
	// making it easier to trace and correlate logs for specific pods.
	logger := mlog.New().WithName("handler").
		WithValues("pod", podName, "namespace", pod.Namespace, "service-account", serviceAccountName)

	// Retrieve serviceAccount object from client cache or API
	// First, attempt to get the ServiceAccount from the client cache (m.client.Get). This is a more efficient operation,
	// as it checks if the resource is already available locally before making an API call.
	// The service account is identified by its name and the pod's namespace.
	serviceAccount := &corev1.ServiceAccount{}
	if err = m.client.Get(ctx, types.NamespacedName{Name: serviceAccountName, Namespace: pod.Namespace}, serviceAccount); err != nil {
		// If the service account is not found in the cache (apierrors.IsNotFound),
		// it may be created or modified externally, so we try fetching it directly from the API server.
		// Fail if error is different from not finding serviceAccount
		if !apierrors.IsNotFound(err) {
			// Log the error and return a bad request response if an unexpected error occurs
			logger.Error("failed to get service account", err)
			return admission.Errored(http.StatusBadRequest, err)
		}

		// Try to retrieve the serviceAccount directly from the API (m.reader.Get) as a fallback.
		// This operation fetches the service account from the API server, ensuring that we get the most up-to-date version.
		err = m.reader.Get(ctx, types.NamespacedName{Name: serviceAccountName, Namespace: pod.Namespace}, serviceAccount)
		if err != nil {
			// Log the error and return a bad request response if the service account cannot be fetched from the API either.
			logger.Error("failed to get service account", err)
			return admission.Errored(http.StatusBadRequest, err)
		}
	}

	// Code below runs only if serviceAccountName could be retrieved

	// Retrieve the main audience from the ServiceAccount annotations
	mainAudience := serviceAccount.Annotations[JWTAudienceAnnotation]
	// Check if audience is set in the serviceAccount
	// If not set, use the default value (JWTAudienceDefault) for the audience
	if mainAudience == "" {
		mainAudience = JWTAudienceDefault
	}

	// Retrieve the extra audiences from the ServiceAccount annotations
	extraAudiences := serviceAccount.Annotations[JWTExtraAudiencesAnnotation]
	// Split the extra audiences string by commas, trimming spaces around each audience
	// This allows multiple extra audiences to be passed as a comma-separated string
	extraAudienceList := []string{}
	for _, aud := range strings.Split(extraAudiences, ",") {
		// Trim spaces around each audience to ensure there are no leading/trailing spaces
		trimmedAud := strings.TrimSpace(aud)
		// Only add non-empty audiences to the list
		if trimmedAud != "" {
			extraAudienceList = append(extraAudienceList, trimmedAud)
		}
	}

	// Retrieve the issuer string from the ServiceAccount annotations
	issuerString := serviceAccount.Annotations[JWTIssuerAnnotation]
	// If the issuer string is not set in the annotations, use the default issuer
	if issuerString == "" {
		issuerString = JWTIssuerDefault
	}

	// Validate the issuer by calling the validateIssuer function
	// This function checks if the issuer is valid based on predefined acceptable values
	issuer, err := validateIssuer(issuerString)
	if err != nil {
		// If the issuer is invalid, print the error and return an error response with a BadRequest status
		fmt.Println("Error:", err)
		return admission.Errored(http.StatusBadRequest, err)
	} else {
		// If the issuer is valid, print the valid issuer to the logs
		fmt.Println("Valid Issuer:", issuer)
	}

	// Switch based on the validated issuer
	switch issuer {
	case SPIFFE:
		// Handle the case when the issuer is SPIFFE
		// Log a message indicating the handling of SPIFFE issuer
		fmt.Println("Handling SPIFFE issuer")
		// Call the function to handle SPIFFE-specific logic (injecting sidecar, configuring providers)
		handleSpiffeIssuer(pod, serviceAccount, mainAudience, extraAudienceList, m)
	case Kubernetes:
		// Handle the case when the issuer is Kubernetes
		// If there are extra audiences specified, log a warning as Kubernetes issuer does not support them
		fmt.Println("Handling Kubernetes issuer")
		if len(extraAudienceList) > 0 {
			logger.Warning("Kubernetes issuer does not support extraAudiences")
		}
		// Call the function to handle Kubernetes-specific logic (setting token file, adding volumes)
		handleKubernetesIssuer(pod, serviceAccount, mainAudience, extraAudienceList, m)
	default:
		// Handle the case when the issuer is unknown
		// Log the error and return a BadRequest response
		fmt.Println("Unknown issuer")
		err = fmt.Errorf("'%s' is not a valid issuer value", issuer)
		return admission.Errored(http.StatusBadRequest, err)
	}

	// Marshal the modified pod to a JSON object for response
	marshaledPod, err := json.Marshal(pod)
	if err != nil {
		// If marshalling fails, log the error and return an InternalServerError response
		logger.Error("failed to marshal pod object", err)
		return admission.Errored(http.StatusInternalServerError, err)
	}

	// Return a patch response to the admission control with the marshaled pod
	return admission.PatchResponseFromRaw(req.Object.Raw, marshaledPod)
}

// handleSpiffeIssuer processes the injection of a Spiffe-helper sidecar and modifies
// the pod containers based on the provided service account and audience information.
// It also handles token file injections for providers and modifies init and main containers accordingly.
func handleSpiffeIssuer(pod *corev1.Pod, serviceAccount *corev1.ServiceAccount, mainAudience string, extraAudiences []string, m *podMutator) {

	// Inject the Spiffe-helper sidecar container into the pod's container spec.
	// This sidecar helps with SPIFFE-based identity handling.
	pod.Spec.Containers = m.injectSpiffeHelperSidecarContainer(pod, m.config, mainAudience, extraAudiences)

	// Retrieve the list of enabled providers by examining the annotations on the service account.
	// Annotations can define the set of providers to be used for identity injection.
	prvs := providers.GetProviders(serviceAccount.Annotations)

	// For each enabled provider, inject the token file (JWT) at the specified path.
	// This step ensures that each provider has access to the necessary token for authentication.
	for _, provider := range prvs {
		provider.AddTokenFile(JWTFilePath) // Add the JWT token file path for each provider.
	}

	// Identify which containers should be skipped during mutation (based on some criteria).
	// These containers are not modified by the following mutation logic.
	skipContainers := getSkipContainers(pod)

	// Apply mutations to init containers and main containers (including the injected sidecar).
	// This is where any customizations or additions (like environment variables) can be applied.
	pod.Spec.InitContainers = m.mutateContainers(pod.Spec.InitContainers, prvs, skipContainers)
	pod.Spec.Containers = m.mutateContainers(pod.Spec.Containers, prvs, skipContainers)
}

// handleKubernetesIssuer processes the injection of a Kubernetes service account token into the pod
// and mutates the pod's containers based on the provided service account and audience information.
// It also manages the token expiration and ensures the service account token volume is projected into the pod.
func handleKubernetesIssuer(pod *corev1.Pod, serviceAccount *corev1.ServiceAccount, mainAudience string, extraAudiences []string, m *podMutator) {

	// Retrieve all enabled providers by reading annotations from the service account.
	// Annotations can specify which providers are to be used for the service account identity.
	prvs := providers.GetProviders(serviceAccount.Annotations)

	// For each enabled provider, inject the service account token file at the specified path.
	// This ensures each provider has access to the token for authentication.
	for _, provider := range prvs {
		provider.AddTokenFile(JWTFilePath) // Adds the JWT token file path for each provider.
	}

	// Retrieve the service account token expiration information.
	// This expiration time might be necessary for handling token rotation or expiration checks.
	serviceAccountTokenExpiration, err := getServiceAccountTokenExpiration(pod, serviceAccount)
	if err != nil {
		// Handle any errors while retrieving the token expiration time (e.g., log or return an error response).
		// logger.Error("failed to get service account token expiration", err)
		// return admission.Errored(http.StatusBadRequest, err)
	}

	// Identify which containers should be skipped during mutation (based on some criteria).
	// This prevents unwanted modifications of containers that should remain unchanged.
	skipContainers := getSkipContainers(pod)

	// Apply mutations to init containers and main containers, including adding the service account token.
	// The mutation logic ensures all containers are properly configured with the required providers and token files.
	pod.Spec.InitContainers = m.mutateContainers(pod.Spec.InitContainers, prvs, skipContainers)
	pod.Spec.Containers = m.mutateContainers(pod.Spec.Containers, prvs, skipContainers)

	// Ensure the projected service account token volume is added to the pod if not already present.
	// This ensures the pod has access to the service account token in the specified path, even across restarts.
	addProjectedServiceAccountTokenVolume(pod, serviceAccountTokenExpiration, mainAudience)
}

// validateIssuer checks if the provided input string corresponds to a valid issuer.
// It trims any surrounding whitespace, then attempts to match the input with a predefined set of valid issuers.
// If the input does not match any valid issuer, it returns an error; otherwise, it returns the validated issuer.
func validateIssuer(input string) (Issuer, error) {
	// Remove leading and trailing whitespace from the input string.
	trimmed := strings.TrimSpace(input)

	// Convert the trimmed string into an Issuer type (which is a string).
	issuer := Issuer(trimmed)

	// Check if the issuer is present in the set of valid issuers.
	// The validIssuers map holds the valid issuer types, and we verify if the input exists as a key in the map.
	if _, exists := validIssuers[issuer]; !exists {
		// If the issuer is not found in the map, return an error indicating the input is invalid.
		return "", fmt.Errorf("'%s' is not a valid issuer value", trimmed)
	}

	// Return the validated issuer if it exists in the validIssuers map.
	return issuer, nil
}

// getServiceAccountTokenExpiration returns the expiration seconds for the project service account token volume.
// It checks the following order of preference for expiration value:
// 1. The annotation in the pod
// 2. The annotation in the service account
// If no annotation is provided, it returns the default expiration.
func getServiceAccountTokenExpiration(pod *corev1.Pod, sa *corev1.ServiceAccount) (int64, error) {
	// Set default expiration value
	serviceAccountTokenExpiration := JWTExpirationDefault
	var err error

	// First, check if the expiration is defined in the pod annotations
	if pod.Annotations != nil && pod.Annotations[JWTExpirationAnnotation] != "" {
		// If the expiration annotation exists, parse it as an int64
		if serviceAccountTokenExpiration, err = strconv.ParseInt(pod.Annotations[JWTExpirationAnnotation], 10, 64); err != nil {
			// Return an error if parsing fails
			return 0, err
		}
	} else if sa.Annotations != nil && sa.Annotations[JWTExpirationAnnotation] != "" {
		// If not found in the pod, check in the service account annotations
		if serviceAccountTokenExpiration, err = strconv.ParseInt(sa.Annotations[JWTExpirationAnnotation], 10, 64); err != nil {
			// Return an error if parsing fails
			return 0, err
		}
	}

	// Validate if the expiration time is within a valid range (3600 - 86400 seconds)
	if !validServiceAccountTokenExpiry(serviceAccountTokenExpiration) {
		// If not valid, return an error with a descriptive message
		return 0, errors.Errorf("token expiration %d not valid. Expected value to be between 3600 and 86400", serviceAccountTokenExpiration)
	}

	// Return the valid expiration value
	return serviceAccountTokenExpiration, nil
}

// validServiceAccountTokenExpiry validates whether the given token expiration time is within the allowed range.
// The expiration time must be between JWTExpirationMin and JWTExpirationMax (inclusive).
func validServiceAccountTokenExpiry(tokenExpiry int64) bool {
	// Check if the token expiration is within the allowed range
	return tokenExpiry <= JWTExpirationMax && tokenExpiry >= JWTExpirationMin
}

// addProjectedServiceAccountTokenVolume adds a projected service account token volume to the pod if it doesn't already exist.
// It ensures that the service account token is projected with the specified expiration time and audience.
func addProjectedServiceAccountTokenVolume(pod *corev1.Pod, serviceAccountTokenExpiration int64, audience string) {
	// Iterate through the pod's volumes to check if the service account token volume already exists
	for _, volume := range pod.Spec.Volumes {
		// Skip non-project volumes
		if volume.Projected == nil {
			continue
		}
		// Iterate through the sources of the projected volume
		for _, pvs := range volume.Projected.Sources {
			// Skip if the source is not a service account token
			if pvs.ServiceAccountToken == nil {
				continue
			}
			// If the token path already matches, exit (token volume already exists)
			if pvs.ServiceAccountToken.Path == JWTVolumeName {
				return
			}
		}
	}

	// If the token volume doesn't exist, add it
	pod.Spec.Volumes = append(
		pod.Spec.Volumes,
		corev1.Volume{
			Name: JWTVolumeName,
			VolumeSource: corev1.VolumeSource{
				Projected: &corev1.ProjectedVolumeSource{
					Sources: []corev1.VolumeProjection{
						{
							ServiceAccountToken: &corev1.ServiceAccountTokenProjection{
								Path:              JWTFileName,                    // The name of the token file
								ExpirationSeconds: &serviceAccountTokenExpiration, // The token expiration time
								Audience:          audience,                       // The audience of the token
							},
						},
					},
				},
			},
		},
	)
}

// addTokenVolumeMount adds the projected token volume mount to the container.
// It ensures that the volume mount is added only if it doesn't already exist.
// This is primarily used to mount the JWT token into containers for SPIFFE-based authentication.
func addTokenVolumeMount(container corev1.Container) corev1.Container {
	// Skip the Spiffe helper sidecar container as it doesn't need a JWT volume mount
	if container.Name == SpiffeHelperSidecarContainerName {
		return container
	}

	// Check if the volume is already mounted in the container
	for _, volume := range container.VolumeMounts {
		// If the volume is already mounted, no need to add it again
		if volume.Name == JWTVolumeName {
			return container
		}
	}

	// If the volume is not mounted, add the JWT volume mount
	container.VolumeMounts = append(container.VolumeMounts,
		corev1.VolumeMount{
			Name:      JWTVolumeName,  // The name of the volume to be mounted
			MountPath: JWTVolumeMount, // The path where the volume will be mounted inside the container
			ReadOnly:  true,           // Mount the volume as read-only
		})

	return container
}

// getSkipContainers returns a map of containers to skip based on the annotation.
// It reads the annotation that contains a semicolon-separated list of container names to skip,
// and ensures the "spiffe-helper" sidecar container is always added to the list if not already present.
func getSkipContainers(pod *corev1.Pod) map[string]struct{} {
	// Retrieve the list of containers to skip from the pod's annotations
	skipContainers := pod.Annotations[SkipContainersAnnotation]

	// If no containers are specified to skip, add the "spiffe-helper" container to the list
	if len(skipContainers) == 0 {
		skipContainers = SpiffeHelperSidecarContainerName
	} else {
		// If there are existing skip containers, append "spiffe-helper" to the list
		skipContainers += ";" + SpiffeHelperSidecarContainerName
	}

	// Split the skipContainers string into a slice using semicolons as delimiters
	skipContainersList := strings.Split(skipContainers, ";")
	m := make(map[string]struct{})

	// Populate the map with the container names to skip, trimming any leading/trailing spaces
	for _, skipContainer := range skipContainersList {
		m[strings.TrimSpace(skipContainer)] = struct{}{}
	}

	// Return the map of containers to skip
	return m
}

// mutateContainers mutates the list of containers by injecting the projected
// service account token volume and environment variables to each container.
// Containers that are listed in the skipContainers map will be excluded from mutation.
func (m *podMutator) mutateContainers(containers []corev1.Container, identityProviders []providers.IdentityProvider, skipContainers map[string]struct{}) []corev1.Container {
	for i := range containers {
		// Skip containers that are present in the skipContainers map
		if _, ok := skipContainers[containers[i].Name]; ok {
			continue
		}

		// Add environment variables to the container if they do not already exist
		containers[i] = addEnvironmentVariables(containers[i], identityProviders)

		// Add the service account projected token volume mount to the container if it doesn't already have it
		// Uncomment the line below to use `addServiceAccountProjectedTokenVolumeMount` instead
		// containers[i] = addServiceAccountProjectedTokenVolumeMount(containers[i])

		// Add the token volume mount (this volume will be injected into the container)
		containers[i] = addTokenVolumeMount(containers[i])
	}
	// Return the mutated list of containers
	return containers
}

// addEnvironmentVariables adds the environment variables needed for the SDK.
// These variables include clientID, tenantID, and the token file path, based on the identity providers.
func addEnvironmentVariables(container corev1.Container, prvs []providers.IdentityProvider) corev1.Container {
	// Iterate over each provider and add the required environment variables
	for _, provider := range prvs {
		// Each provider may have its own method for adding environment variables
		provider.AddEnvironmentVariables(&container)
	}

	// Return the container with the added environment variables
	return container
}

// injectSpiffeHelperSidecarContainer adds a SPIFFE helper sidecar container to the pod if it doesn't already exist.
// It also sets up the necessary volumes and environment variables for the sidecar.
func (m *podMutator) injectSpiffeHelperSidecarContainer(pod *corev1.Pod, c *config.Config, mainAudience string, extraAudiences []string) []corev1.Container {
	// Get the list of containers in the pod
	containers := pod.Spec.Containers

	// Check if the sidecar container already exists, if so, return the existing containers
	for _, container := range containers {
		if container.Name == SpiffeHelperSidecarContainerName {
			fmt.Printf("pod %s/%s already has the spiffe-helper container\n", pod.Namespace, pod.Name)
			return containers
		}
	}

	// Construct extra audiences string or use the default if none provided
	var extraAudiencesString string
	if len(extraAudiences) > 0 {
		extraAudiencesString = fmt.Sprintf("[\"%s\"]", strings.Join(extraAudiences, "\", \""))
	} else {
		extraAudiencesString = SpiffeHelperJWTExtraAudiencesDefault
	}

	// Set read-only flag for the volumes
	readOnly := true

	// Add volumes required for the SPIFFE helper sidecar
	pod.Spec.Volumes = append(pod.Spec.Volumes,
		corev1.Volume{
			Name: SpiffeHelperSidecarContainerWorkloadAPIVolumeName,
			VolumeSource: corev1.VolumeSource{
				CSI: &corev1.CSIVolumeSource{
					Driver:   "csi.spiffe.io", // SPIFFE driver
					ReadOnly: &readOnly,
				},
			},
		},
		corev1.Volume{
			Name: SpiffeHelperSidecarContainerConfigVolumeName,
			VolumeSource: corev1.VolumeSource{
				EmptyDir: &corev1.EmptyDirVolumeSource{}, // Temporary empty directory
			},
		},
		corev1.Volume{
			Name: JWTVolumeName,
			VolumeSource: corev1.VolumeSource{
				EmptyDir: &corev1.EmptyDirVolumeSource{}, // Temporary empty directory for JWT
			},
		})

	// Append the new sidecar container with appropriate environment variables and volume mounts
	containers = append(containers, []corev1.Container{{
		Name:            SpiffeHelperSidecarContainerName,
		Image:           c.SpiffeHelperSidecarImage,
		ImagePullPolicy: corev1.PullAlways,
		VolumeMounts: []corev1.VolumeMount{
			// Mount volumes to the sidecar container
			{
				Name:      SpiffeHelperSidecarContainerWorkloadAPIVolumeName,
				MountPath: SpiffeHelperSidecarContainerWorkloadAPIVolumeMount,
				ReadOnly:  readOnly,
			},
			{
				Name:      SpiffeHelperSidecarContainerConfigVolumeName,
				MountPath: SpiffeHelperSidecarContainerConfigVolumeMount,
			},
			{
				Name:      JWTVolumeName,
				MountPath: JWTVolumeMount,
			},
		},
		Env: []corev1.EnvVar{
			// Set environment variables for the sidecar
			{
				Name:  SpiffeHelperAgentAddressEnvVar,
				Value: SpiffeHelperAgentAddressDefault,
			},
			{
				Name:  SpiffeHelperDaemonModeEnvVar,
				Value: SpiffeHelperDaemonModeDefault,
			},
			{
				Name:  SpiffeHelperJWTAudienceEnvVar,
				Value: mainAudience,
			},
			{
				Name:  SpiffeHelperJWTFileName,
				Value: SpiffeHelperJWTFileNameDefault,
			},
			{
				Name:  SpiffeHelperJWTFileMode,
				Value: SpiffeHelperJWTFileModeDefault,
			},
			{
				Name:  SpiffeHelperJWTBundleFile,
				Value: SpiffeHelperJWTBundleFileDefault,
			},
			{
				Name:  SpiffeHelperJWTBundleMode,
				Value: SpiffeHelperJWTBundleModeDefault,
			},
			{
				Name:  SpiffeHelperJWTExtraAudiencesEnvVar,
				Value: extraAudiencesString,
			},
		},
		// Set security context for the sidecar container
		SecurityContext: &corev1.SecurityContext{
			AllowPrivilegeEscalation: ptr.To(false), // Prevent privilege escalation
			Capabilities: &corev1.Capabilities{
				Drop: []corev1.Capability{"ALL"}, // Drop all capabilities for security
			},
			Privileged:             ptr.To(false),
			ReadOnlyRootFilesystem: ptr.To(true),
			RunAsNonRoot:           ptr.To(true),
		},
	}}...)

	// Return the updated list of containers
	return containers
}
