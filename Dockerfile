FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    git curl ca-certificates golang && rm -rf /var/lib/apt/lists/*

ENV PATH="$PATH:/root/go/bin"
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

RUN CGO_ENABLED=1 go install github.com/projectdiscovery/katana/cmd/katana@latest && \
    go install github.com/tomnomnom/gf@latest && \
    mkdir -p /root/.gf && \
    cp $(go env GOPATH)/pkg/mod/github.com/tomnomnom/gf@*/examples/* /root/.gf || true && \
    git clone https://github.com/1ndianl33t/Gf-Patterns /root/.gf_patterns && \
    cp /root/.gf_patterns/*.json /root/.gf

COPY . .
ENTRYPOINT ["python", "-m", "directhit"]
