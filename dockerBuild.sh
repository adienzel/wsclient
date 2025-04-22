#!/bin/bash
set -e
IMAGE_NAME=$1
if [ -z "$IMAGE_NAME" ]; then
  echo "Usage: ./build.sh <image-name>"
  exit 1
fi
docker build -t $IMAGE_NAME .
