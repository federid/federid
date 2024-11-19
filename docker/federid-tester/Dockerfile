FROM debian:bookworm-slim


ENV DEBIAN_FRONTEND=noninteractive

# Make sure the package repository is up to date.
# Make sure the package repository is up to date.
RUN apt-get update && \
    apt-get install -qy apt-utils vim wget curl unzip bash-completion software-properties-common

## Install gcloud
RUN echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" | \
tee -a /etc/apt/sources.list.d/google-cloud-sdk.list && \
curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | \
apt-key --keyring /usr/share/keyrings/cloud.google.gpg add - && \
apt-get update && apt-get install -qy google-cloud-cli

## Install awscli
#RUN apt-get install -qy awscli
RUN curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip" &&\
unzip awscliv2.zip && \
./aws/install

## Install azure-cli
RUN curl -sL https://aka.ms/InstallAzureCLIDeb | bash


CMD [ "sleep", "infinity" ]
