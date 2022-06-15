# Run as any user with execute permission on 'docker ps, image, exec -ps el, inspect".
# Replace the (EDITME) with the hostname.
# Run:  docker_imv21-04-04.sh >> (EDITME).log

echo "hostname"
hostname
echo "id"
id
date
echo "docker ps --quiet --all | xargs docker inspect --format '{{ .Id }}: Privileged={{ .HostConfig.Privileged }}'"
docker ps --quiet --all | xargs docker inspect --format '{{ .Id }}: Privileged={{ .HostConfig.Privileged }}'
	
# The command above should return a state for each container instance.

echo "docker ps --quiet --all | xargs docker inspect --format '{{ .Id }}: UsernsMode={{ .HostConfig.UsernsMode }}'"
docker ps --quiet --all | xargs docker inspect --format '{{ .Id }}: UsernsMode={{ .HostConfig.UsernsMode }}'
	
# The command above should show the host user namespace.

echo "docker images --format "table {{.Repository}}\t{{.Tag}}\t{{.ID}}\t{{.CreatedAt}}\t{{.Size}}" "
docker images --format "table {{.Repository}}\t{{.Tag}}\t{{.ID}}\t{{.CreatedAt}}\t{{.Size}}" 
# The command above should return the list of images with the details
echo "docker ps --quiet --all | xargs docker inspect --format '{{ .Id }}: Volumes={{ .Mounts }}'"
docker ps --quiet --all | xargs docker inspect --format '{{ .Id }}: Volumes={{ .Mounts }}'
# The command above should return the list of current mapped directories and whether they are mounted in read-write mode for each container instance.


for cid in $(docker ps --format '{{.ID}}' --no-trunc)
do 
	echo "docker ps --format '{{.Image}}' --filter id=$cid"
	docker ps --format '{{.Image}}' --filter id=$cid
	echo ""
	echo "docker ps --no-trunc --filter id=$cid"
	docker ps --no-trunc --filter id=$cid
	echo "docker exec $cid ps -el"
	docker exec $cid ps -el
	echo ""
done
# the commands above should return the processes in execution within the containers in execution
