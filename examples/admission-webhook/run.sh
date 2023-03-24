#!/bin/bash

set -euo pipefail

nerdctl volume create gocache || echo ""
nerdctl volume create gcache || echo ""

ROOT=$(git rev-parse --show-toplevel)

cd $ROOT

export COMMIT="$(git rev-parse HEAD)"

# For storing temporary files that version control will ignore, such as certs
mkdir -p tmp

# Create required certs
examples/admission-webhook/certs/certs.sh

nerdctl build --namespace k8s.io -f examples/admission-webhook/Dockerfile -t k8sadmission:latest . 

kubectl -n k8sadmission apply -f examples/admission-webhook/k8s/namespace.yaml

# Upload the TLS cert and replace if exists
kubectl -n k8sadmission create secret tls k8sadmission --cert=tmp/server.crt --key=tmp/server.key --dry-run=client -oyaml | kubectl -n k8sadmission apply -f -

kubectl -n k8sadmission apply -f examples/admission-webhook/k8s/deployment.yaml

kubectl -n k8sadmission apply -f examples/admission-webhook/k8s/service.yaml

# Upload the falco config
kubectl -n k8sadmission create configmap falcoyaml --from-file=./examples/admission-webhook/falco.yaml

# upload the falco rules
kubectl -n k8sadmission create configmap falcorules --from-file=./rules/k8s_admission_rules.yaml

# Substitute in the correct CA into the webhook
export CABUNDLEB64="$(cat tmp/rootCA.pem | base64 | tr -d '\n')"
cat examples/admission-webhook/k8s/webhook.yaml | envsubst | kubectl -n k8sadmission apply -f -
unset CABUNDLEB64

kubectl -n k8sadmission rollout restart deployment/k8sadmission
