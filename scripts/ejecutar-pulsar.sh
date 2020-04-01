docker run --rm -it \
    -p 6650:6650 \
    -p 8080:8080 \
    -v $PWD/data:/pulsar/data \
    apachepulsar/pulsar:latest \
    bin/pulsar standalone
