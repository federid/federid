DOCKER_BUILDKIT=0 docker build -t federid/spiffe-helper:latest -f Dockerfile.spiffe-helper .
docker push federid/spiffe-helper:latest
