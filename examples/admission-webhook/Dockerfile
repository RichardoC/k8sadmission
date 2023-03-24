FROM falcosecurity/falco as builder

RUN apt update ; apt --fix-broken install -y ; apt install -y wget && wget https://go.dev/dl/go1.19.5.linux-amd64.tar.gz && tar -C /usr/local -xzf go1.19.5.linux-amd64.tar.gz && export PATH=$PATH:/usr/local/go/bin

# nerdctl run --rm -it -v$(pwd):/example:rw -v gocache:/root/go -v gcache:/root/.cache falco-plugin-builder -c 'export PATH=$PATH:/usr/local/go/bin && cd /example && make clean && make && /usr/bin/falco -u  -c /example/examples/running-locally/falco.yaml  -r /example/rules/k8s_admission_rules.yaml --disable-source syscall'

# Being specific about files to copy, to prevent unneeded rebuilds
COPY ./plugin /k8sadmission/plugin
COPY ./pkg /k8sadmission/pkg
COPY ./go* /k8sadmission/
COPY ./Makefile /k8sadmission/

WORKDIR /k8sadmission

RUN export PATH=$PATH:/usr/local/go/bin ; make

FROM falcosecurity/falco

COPY --from=builder /k8sadmission/libk8sadmission.so /usr/share/falco/plugins/
# COPY --from=builder /usr/share/falco/plugins/* /usr/share/falco/plugins/



ENTRYPOINT /usr/bin/falco -u -r /etc/falco/k8s_admission_rules.yaml --disable-source syscall

CMD [ "/bin/bash", "-c" ]
