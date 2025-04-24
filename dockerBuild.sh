#!/bin/bash
# Check if the correct number of arguments is provided
if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <username> <image_name>"
    exit 1
fi

USERNAME=$1
IMAGE_NAME=$2

# Build the Docker image
docker build -t ${USERNAME}/${IMAGE_NAME} .

# Push the Docker image to Docker Hub
#docker push ${USERNAME}/${IMAGE_NAME}
