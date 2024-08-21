## container setup

### to use this script test environment

docker buildx build -t azure_like_ubuntu .

### start
docker-compose up


## azure setup
This requires a VM with keyvault access through a managed identity

### WIP notes:
1. attempting to use a docker container as a test environment did not work out, because the setup script uses systemd to run eventstore.
docker does not really support using systemd without some serious hacks, podman might but attempts at using a compose.yaml failed