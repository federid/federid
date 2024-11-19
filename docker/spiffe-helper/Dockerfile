#FROM ghcr.io/spiffe/spiffe-helper:0.8.0 AS spiffe-helper
FROM federid/spiffe-helper:extraAudiences AS spiffe-helper
FROM debian:bookworm

# Set the working directory
WORKDIR /

# Copy the spiffe-helper binary from the first stage
COPY --link --from=spiffe-helper /spiffe-helper /spiffe-helper

ENV CONFIG_PATH="/opt/spiffe-helper"
ENV CONFIG_FILE_NAME="helper.conf"
ENV CONFIG_FILE="${CONFIG_PATH}/${CONFIG_FILE_NAME}"

# Set environment variables
ENV AGENT_ADDRESS=/spiffe-workload-api/spire-agent.sock
ENV DAEMON_MODE=true
ENV JWT_SVIDS_JWT_AUDIENCE="federid"
ENV JWT_SVIDS_JWT_EXTRA_AUDIENCES="[]"
ENV JWT_SVIDS_JWT_SVID_FILE_NAME="/run/spiffe-helper/token"
ENV JWT_SVID_FILE_MODE="0440"
ENV JWT_BUNDLE_FILE_NAME="bundle.json"
ENV JWT_BUNDLE_FILE_MODE="0444"
# Create the entrypoint script to generate helper.conf and start spiffe-helper
RUN echo '#!/bin/sh' > /entrypoint.sh && \
    echo 'echo "Creating "${CONFIG_FILE}" file..."' >> /entrypoint.sh && \
    echo 'cat <<EOF > "${CONFIG_FILE}"' >> /entrypoint.sh && \
    echo 'agent_address = "${AGENT_ADDRESS}"' >> /entrypoint.sh && \
    echo 'daemon_mode = ${DAEMON_MODE}' >> /entrypoint.sh && \
    echo 'jwt_svids = [{jwt_audience="${JWT_SVIDS_JWT_AUDIENCE}", jwt_extra_audiences=${JWT_SVIDS_JWT_EXTRA_AUDIENCES}, jwt_svid_file_name="${JWT_SVIDS_JWT_SVID_FILE_NAME}"}]' >> /entrypoint.sh && \
    echo 'jwt_svid_file_mode = ${JWT_SVID_FILE_MODE}' >> /entrypoint.sh && \
    echo 'jwt_bundle_file_name = "${JWT_BUNDLE_FILE_NAME}"' >> /entrypoint.sh && \
    echo 'jwt_bundle_file_mode = ${JWT_BUNDLE_FILE_MODE}' >> /entrypoint.sh && \
    echo 'EOF' >> /entrypoint.sh && \
    echo 'echo "Configuration file:"' >> /entrypoint.sh && \
    echo 'cat "${CONFIG_FILE}"' >> /entrypoint.sh && \
    echo 'chmod 0444 "${CONFIG_FILE}"' >> /entrypoint.sh && \
    echo 'echo "Starting spiffe-helper..."' >> /entrypoint.sh && \
    echo 'exec /spiffe-helper -config "${CONFIG_FILE}"' >> /entrypoint.sh

RUN cat /entrypoint.sh

# Make the entrypoint script executable
RUN chmod +x /entrypoint.sh

# Create the directory for the helper configuration file
RUN mkdir -p ${CONFIG_PATH}

RUN touch ${CONFIG_FILE}
RUN chown 65532:65532 ${CONFIG_FILE}

# Kubernetes runAsNonRoot requires USER to be numeric
USER 65532:65532

# Use the shell script as the entrypoint
ENTRYPOINT ["/entrypoint.sh"]

CMD []
