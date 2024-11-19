DOCKER_BUILDKIT=0 docker build -t federid/tester:latest -f Dockerfile.federid-tester .
docker push federid/tester:latest
