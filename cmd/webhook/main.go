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

package main

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"os"

	"github.com/open-policy-agent/cert-controller/pkg/rotator"
	"github.com/spf13/cobra"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"monis.app/mlog"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/apiutil"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/manager/signals"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/webhook"

	"github.com/federid/federid/pkg/metrics"
	"github.com/federid/federid/pkg/util"
	wh "github.com/federid/federid/pkg/webhook"
)

// webhooks holds the information about the webhooks used by the application.
// Each entry in the slice represents a webhook, including its name and type.
var webhooks = []rotator.WebhookInfo{
	{
		// Name of the webhook, used for identifying the webhook configuration.
		Name: "federid-webhook-mutating-webhook-configuration",

		// Type of the webhook. In this case, it is a mutating webhook, which modifies incoming requests.
		Type: rotator.Mutating,
	},
}

// Constants for the names of various Kubernetes resources used in the webhook setup.
const (
	// secretName is the name of the Kubernetes secret that holds the webhook server's certificate.
	secretName = "federid-webhook-server-cert"

	// serviceName is the name of the Kubernetes service for the webhook.
	serviceName = "federid-webhook-service"

	// caName is the name of the certificate authority (CA) used to sign the webhook's certificate.
	caName = "federid-ca"

	// caOrganization specifies the organization name for the certificate authority.
	caOrganization = "federid"
)

var (
	// From Azure: These variables hold configuration values for Azure-related settings.
	tlsMinVersion       string // Minimum TLS version to use for secure connections, e.g., "1.2", "1.3".
	metricsBackend      string // Specifies the backend for metrics collection, e.g., "prometheus".
	webhookCertDir      string // Directory for storing webhook certificates. Default value is "/certs".
	healthAddr          string // Address and port for the health endpoint (default is ":9440").
	metricsAddr         string // Address and port for the metrics endpoint (default is ":8095").
	disableCertRotation bool   // Flag to disable automatic certificate rotation for webhook TLS certificates.
	logLevel            string // Log level for the application. Can be set to "info", "debug", "trace", etc.

	// DNSName is constructed from the service name and namespace for the webhook server.
	// It is in the format "<service-name>.<namespace>.svc".
	dnsName = fmt.Sprintf("%s.%s.svc", serviceName, util.GetNamespace())

	// scheme is the runtime scheme used to register Kubernetes API resources.
	scheme = runtime.NewScheme()

	// entryLog is a logger for the entrypoint, providing logs related to the initialization of the application.
	entryLog = mlog.New().WithName("entrypoint")
)

// rootCmd represents the base command when called without any subcommands.
// It is the entry point of the application and is typically responsible for setting up the CLI structure.
// When the user runs the application without specifying a subcommand, this command is invoked.
var rootCmd = &cobra.Command{
	// Use is the one-liner that will be used for the command in the CLI.
	// It is the name of the application or the command to be executed.
	Use: "federid-webhook", // Name of the CLI tool

	// Short provides a brief description of the command.
	// This description will be shown when the user lists the available commands.
	Short: "A webhook for federated identity management in Kubernetes", // Updated to reflect the app's purpose

	// Long provides a more detailed explanation of what the command does.
	// This description is displayed when the user runs the help command (e.g., `federid-webhook --help`).
	// The long description can span multiple lines and typically includes example usage or additional details.
	Long: `Federid-webhook is a tool for managing federated identities within a Kubernetes cluster.
It integrates with cloud identity providers such as Azure, AWS, and GCP, 
allowing workloads to authenticate and access cloud resources using identity federation.

This application helps generate the necessary webhook server and configurations to support identity federation in Kubernetes.`,

	// Run is the function that is executed when the root command is invoked directly (without subcommands).
	// In this case, it does nothing (empty implementation), but it can be used to define the root command's behavior.
	// If the application has no subcommands, the behavior defined here would be triggered.
	Run: func(cmd *cobra.Command, args []string) {
		// Here, you can define the action to take when the root command is called.
		// For example, you could initialize the application or show an introductory message.
	},
}

// main is the entry point for the application.
// It calls the Execute function which initializes and runs the root command.
// If the Execute function returns an error, the program exits with a status code of 1.
func main() {
	// Execute initializes and runs the root command, processing any flags or arguments passed to the CLI.
	// If an error occurs during the execution, it will be returned.
	err := Execute()

	// If there was an error during execution, exit the program with a non-zero status code.
	// This signals that the program encountered an issue.
	if err != nil {
		os.Exit(1)
	}
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This function is called by main.main() and should only be executed once to initialize the rootCmd.
// It is responsible for setting up logging, initializing configurations, starting the metrics exporter,
// and running the controller manager.
func Execute() error {
	defer mlog.Setup()() // Set up and tear down the logger when execution is done.

	// Set up signal handler for graceful shutdown on receiving termination signals.
	ctx := signals.SetupSignalHandler()

	// Validate and set the log level and format globally using the value from the logLevel flag.
	if err := mlog.ValidateAndSetLogLevelAndFormatGlobally(ctx, mlog.LogSpec{
		Level:  mlog.LogLevel(logLevel), // Log level set via --log-level flag.
		Format: mlog.FormatJSON,         // Log format is set to JSON.
	}); err != nil {
		return fmt.Errorf("invalid --log-level set: %w", err) // Return error if log level is invalid.
	}

	// Log the namespace the application is running in.
	entryLog.Info("Initializing in namespace:", "namespace", util.GetNamespace())

	// Set up the global logger using Logr.
	log.SetLogger(mlog.Logr())

	// Get the Kubernetes client configuration or die trying.
	config := ctrl.GetConfigOrDie()

	// Parse the TLS version from the command-line argument and return an error if invalid.
	tlsVersion, err := parseTLSVersion(tlsMinVersion)
	if err != nil {
		return fmt.Errorf("entrypoint: unable to parse TLS version: %w", err) // Return error if parsing fails.
	}

	// Log initialization of the metrics backend.
	entryLog.Info("initializing metrics backend", "backend", metricsBackend)
	// Initialize the metrics exporter based on the chosen backend.
	if err := metrics.InitMetricsExporter(metricsBackend); err != nil {
		return fmt.Errorf("entrypoint: failed to initialize metrics exporter: %w", err) // Return error if exporter fails.
	}

	// Set up the webhook server options, including certificate directory and TLS configuration.
	serverOpts := webhook.Options{
		CertDir: webhookCertDir,                                                           // Directory for webhook TLS certificates.
		TLSOpts: []func(c *tls.Config){func(c *tls.Config) { c.MinVersion = tlsVersion }}, // Set the minimum TLS version.
	}

	// Create a new controller manager with the provided configuration and options.
	mgr, err := ctrl.NewManager(config, ctrl.Options{
		Scheme:                 scheme,     // Register the scheme to the manager.
		LeaderElection:         false,      // Disable leader election.
		HealthProbeBindAddress: healthAddr, // Set health probe address.
		Metrics: metricsserver.Options{
			BindAddress: metricsAddr, // Set metrics endpoint address.
		},
		WebhookServer:  webhook.NewServer(serverOpts), // Initialize the webhook server with options.
		MapperProvider: apiutil.NewDynamicRESTMapper,  // Set the REST API mapper provider.
	})
	if err != nil {
		return fmt.Errorf("entrypoint: unable to set up controller manager: %w", err) // Return error if manager setup fails.
	}

	// Channel used to notify when certificate setup is complete.
	setupFinished := make(chan struct{})

	// If certificate rotation is enabled, set up certificate rotation for webhook server.
	if !disableCertRotation {
		entryLog.Info("setting up cert rotation")
		// Add a cert rotator to the manager to automatically manage certificate lifecycle.
		if err := rotator.AddRotator(mgr, &rotator.CertRotator{
			SecretKey: types.NamespacedName{
				Namespace: util.GetNamespace(),
				Name:      secretName,
			},
			CertDir:        webhookCertDir,
			CAName:         caName,
			CAOrganization: caOrganization,
			DNSName:        dnsName,
			IsReady:        setupFinished, // Channel to signal when setup is done.
			Webhooks:       webhooks,      // List of webhooks that will use the certificates.
		}); err != nil {
			return fmt.Errorf("entrypoint: unable to set up cert rotation: %w", err) // Return error if cert rotation setup fails.
		} else {
			entryLog.Info("cert rotator set up") // Log success when cert rotation setup is complete.
		}
	} else {
		// If cert rotation is disabled, close the setupFinished channel immediately.
		close(setupFinished)
	}

	// Set up health and readiness probes for the controller manager.
	setupProbeEndpoints(mgr, setupFinished)

	// Start the webhook server asynchronously, passing the setupFinished channel to ensure it's ready.
	go setupWebhook(mgr, setupFinished)

	// Log and start the manager, which will run the controller, webhooks, and health checks.
	entryLog.Info("starting manager")
	if err := mgr.Start(ctx); err != nil {
		return fmt.Errorf("entrypoint: unable to run manager: %w", err) // Return error if manager fails to start.
	}

	return nil // Return nil if everything is successfully set up and started.
}

// init is called automatically during the initialization phase of the program.
// It sets up the command-line flags for the application and registers them with the root command (rootCmd).
// These flags allow users to configure various application settings via command-line arguments.
func init() {
	// Add clientgoscheme to the scheme to support Kubernetes API types.
	// This is typically needed for Kubernetes client setup.
	_ = clientgoscheme.AddToScheme(scheme)

	// Azure-related command-line flags setup
	// Set the minimum TLS version to be used by the webhook server.
	// Defaults to TLS version 1.3 if not specified.
	rootCmd.Flags().StringVar(&tlsMinVersion, "tls-min-version", "1.3", "Minimum TLS version")

	// Set the backend for metrics collection.
	// By default, Prometheus is used as the backend for monitoring metrics.
	rootCmd.Flags().StringVar(&metricsBackend, "metrics-backend", "prometheus", "Backend used for metrics")

	// Set the directory where webhook certificates are stored.
	// Defaults to "/certs" if not specified.
	rootCmd.Flags().StringVar(&webhookCertDir, "webhook-cert-dir", "/certs", "Webhook certificates dir to use. Defaults to /certs")

	// Set the address for the health endpoint.
	// The health check will bind to this address to provide health status information.
	rootCmd.Flags().StringVar(&healthAddr, "health-addr", ":9440", "The address the health endpoint binds to")

	// Set the address for the metrics endpoint.
	// This is where the metrics data will be exposed for scraping by monitoring systems.
	rootCmd.Flags().StringVar(&metricsAddr, "metrics-addr", ":8095", "The address the metrics endpoint binds to")

	// Flag to disable the automatic generation and rotation of TLS certificates/keys for the webhook.
	// If set to true, manual certificate management will be required.
	rootCmd.Flags().BoolVar(&disableCertRotation, "disable-cert-rotation", false, "disable automatic generation and rotation of webhook TLS certificates/keys")

	// Set the log level for the application.
	// The verbosity level of logs can be set to "info", "debug", "trace", or "all" for more detailed logging.
	// The default is "info".
	rootCmd.Flags().StringVar(&logLevel, "log-level", "info", "In order of increasing verbosity: unset (empty string), info, debug, trace and all.")

	// Marking flags as required. In this case, there are no required flags specified.
	// This loop would be used to mark certain flags as required if needed.
	requiredFlags := []string{""}
	for _, flag := range requiredFlags {
		// Marking the flag as required so that the user must provide it via command line.
		rootCmd.MarkFlagRequired(flag)
	}
}

// setupProbeEndpoints sets up custom readiness and liveness probes for the application.
// These probes ensure that the application is only marked as ready when the webhook server has completed its setup (e.g., certificate injection).
//
// mgr: The manager instance that provides access to the webhook server and health check functionality.
// setupFinished: A channel that signals when the setup (such as certificate generation and validator startup) has completed.
func setupProbeEndpoints(mgr ctrl.Manager, setupFinished chan struct{}) {
	// Block the readiness probe until the mutating webhook has been fully registered and the certificates are ready.
	// The standard mgr.GetWebhookServer().StartedChecker() can't be used directly here,
	// because it would start the webhook server. However, we need to delay the readiness check until
	// the certificates have been injected and the validator has started.
	checker := func(req *http.Request) error {
		select {
		case <-setupFinished:
			// Once the setup has finished, call the real readiness check to verify the webhook server is started.
			return mgr.GetWebhookServer().StartedChecker()(req)
		default:
			// If the setup is not yet complete, return an error indicating that certificates are not ready.
			return fmt.Errorf("certs are not ready yet")
		}
	}

	// Add a health check endpoint ('healthz') that will use the custom readiness check.
	// This ensures that the health check will only pass once the setup is complete.
	if err := mgr.AddHealthzCheck("healthz", checker); err != nil {
		// If adding the health check fails, panic with an error message.
		panic(fmt.Errorf("unable to add healthz check: %w", err))
	}

	// Add a readiness check endpoint ('readyz') using the same custom readiness check.
	// This ensures that the application is marked as ready only when the certificates and webhook server are fully initialized.
	if err := mgr.AddReadyzCheck("readyz", checker); err != nil {
		// If adding the readiness check fails, panic with an error message.
		panic(fmt.Errorf("unable to add readyz check: %w", err))
	}

	// Log a message indicating that both healthz and readyz checks have been successfully added.
	entryLog.Info("added healthz and readyz check")
}

// setupWebhook sets up a webhook server and registers an admission controller for pod mutation.
// It blocks until the setup (such as certificate generation) is completed, then it configures
// the webhook server to handle pod mutation requests.
//
// mgr: The manager instance responsible for managing the webhook server, client, API reader, and scheme.
// setupFinished: A channel that signals when the setup (e.g., certificate generation) is finished and it’s safe to register the webhook.
func setupWebhook(mgr manager.Manager, setupFinished chan struct{}) {
	// Block and wait for the setup (certificate generation) to complete.
	// The function will pause execution here until it receives a signal via the 'setupFinished' channel.
	<-setupFinished

	// Retrieve the webhook server from the manager.
	// This will be used to register the admission controller handler for the pod mutation.
	hookServer := mgr.GetWebhookServer()

	// Log the start of the webhook registration process for pod mutation.
	entryLog.Info("registering webhook to the webhook server")

	// Create a new pod mutator. This handler will be used to mutate incoming pod admission requests.
	// It is initialized with the manager's client, API reader, and scheme.
	podMutator, err := wh.NewPodMutator(mgr.GetClient(), mgr.GetAPIReader(), mgr.GetScheme())
	if err != nil {
		// If there is an error setting up the pod mutator, panic and provide a descriptive error message.
		panic(fmt.Errorf("unable to set up pod mutator: %w", err))
	}

	// Register the pod mutator to the webhook server at the "/mutate-v1-pod" endpoint.
	// The pod mutator will handle pod admission requests at this URL, modifying the pod as needed before admission.
	hookServer.Register("/mutate-v1-pod", &webhook.Admission{Handler: podMutator})
}

// parseTLSVersion parses a string representation of a TLS version and returns the corresponding constant from the tls package.
// It returns the numeric value of the TLS version and an error if the provided version is invalid.
//
// tlsVersion: The string representation of the desired TLS version (e.g., "1.0", "1.1", "1.2", "1.3").
//
// Returns:
//
//	uint16: The numeric representation of the TLS version (e.g., tls.VersionTLS10 for "1.0").
//	error: An error is returned if the provided TLS version is invalid, including an error message with acceptable versions.
func parseTLSVersion(tlsVersion string) (uint16, error) {
	// Match the provided TLS version to the corresponding tls package constant
	switch tlsVersion {
	case "1.0":
		// Return the numeric value for TLS 1.0
		return tls.VersionTLS10, nil
	case "1.1":
		// Return the numeric value for TLS 1.1
		return tls.VersionTLS11, nil
	case "1.2":
		// Return the numeric value for TLS 1.2
		return tls.VersionTLS12, nil
	case "1.3":
		// Return the numeric value for TLS 1.3
		return tls.VersionTLS13, nil
	default:
		// Return an error if the provided TLS version is invalid
		return 0, fmt.Errorf("invalid TLS version. Must be one of: 1.0, 1.1, 1.2, 1.3")
	}
}
