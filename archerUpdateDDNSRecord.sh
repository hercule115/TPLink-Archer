#!/usr/bin/env bash
set -e

TOOLS='/usr/local/tools'

IMAGE="mypython38:1.1"
ENTRY_POINT="python3 ${TOOLS}/TPLink-Archer/archerUpdateDDNSRecord.py -v"
CONTAINER="archerUpdateDDNSRecord"

# Clear old/exited container
if [ ! "$(docker ps -q -f name=${CONTAINER})" ]; then
    #echo 'not found'
    if [ "$(docker ps -aq -f status=exited -f name={CONTAINER})" ]; then
        # cleanup
	echo "Cleaning old container"
        docker rm {CONTAINER}
    fi
fi

#docker rm --force archerUpdateDDNSRecord || true
# -d --restart unless-stopped
# python-noipy-archer

# Run the python-noipy-archer image
docker run \
       --rm \
       --name archerUpdateDDNSRecord \
       -v /${TOOLS}/nginx-7080/html:/${TOOLS}/nginx-7080/html:rw \
       -v /${TOOLS}/TPLink-Archer:/${TOOLS}/TPLink-Archer:rw \
       ${IMAGE} \
       ${ENTRY_POINT}
