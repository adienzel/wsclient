#!/bin/bash
IMAGE_NAME=$1
cat <<EOF > pod.yaml
apiVersion: v1
kind: Pod
metadata:
  name: ws-client
spec:
  containers:
  - name: ws-client
    image: $IMAGE_NAME
    env:
    - name: SERVER_ADDR
      value: "example.com"
    - name: START_PORT
      value: "443"
    - name: PORT_COUNT
      value: "1"
    - name: NUM_CLIENTS
      value: "10"
    - name: MESSAGES_PER_CLIENT
      value: "100"
    - name: MESSAGES_PER_SECOND
      value: "4"
    - name: CLIENT_CERT
      value: "/certs/client.crt"
    - name: CLIENT_KEY
      value: "/certs/client.key"
    - name: CA_CERT
      value: "/certs/ca.crt"
    - name: PROM_PUSHGATEWAY_URL
      value: "http://pushgateway:9091"
    volumeMounts:
    - name: certs
      mountPath: /certs
      readOnly: true
  volumes:
  - name: certs
    secret:
      secretName: mtls-certs
EOF
