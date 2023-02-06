FROM falcosecurity/falco

RUN apt update ; apt --fix-broken install -y ; apt install -y wget && wget https://go.dev/dl/go1.19.5.linux-amd64.tar.gz && tar -C /usr/local -xzf go1.19.5.linux-amd64.tar.gz && export PATH=$PATH:/usr/local/go/bin

ENTRYPOINT [ "/bin/bash" ]