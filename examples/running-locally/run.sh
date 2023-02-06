#!/bin/bash

nerdctl volume create gocache || echo ""
nerdctl volume create gcache || echo ""

# nerdctl build -f examples/running-locally/Dockerfile  -t falco-plugin-builder .

# nerdctl run --rm -it -v$(pwd):/example:rw falco-plugin-builder -c 'export PATH=$PATH:/usr/local/go/bin && cd /example && make clean && make && /usr/bin/falco -u  -c /example/examples/running-locally/falco.yaml  -r /example/examples/running-locally/falco_rules.yaml  --list-plugins'

nerdctl run --rm -it -v$(pwd):/example:rw -v gocache:/root/go -v gcache:/root/.cache falco-plugin-builder -c 'export PATH=$PATH:/usr/local/go/bin && cd /example && make clean && make && /usr/bin/falco -u  -c /example/examples/running-locally/falco.yaml  -r /example/rules/k8s_admission_rules.yaml --disable-source syscall -k'
