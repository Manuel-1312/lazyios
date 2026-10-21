# Renders docs/demo.gif from docs/demo/demo.tape with VHS.
#
#   docker build -f docs/demo/Dockerfile -t lazyios-demo .
#   docker run --rm -v "$PWD/docs:/out" -w /out lazyios-demo demo/demo.tape
FROM ghcr.io/charmbracelet/vhs:v0.11.0

RUN apt-get update \
    && apt-get install -y --no-install-recommends python3-venv python3-pip \
    && rm -rf /var/lib/apt/lists/*

# --demo never loads pymobiledevice3, so only textual is needed for the recording
COPY pyproject.toml README.md LICENSE /src/
COPY src /src/src
RUN python3 -m venv /opt/lazyios \
    && /opt/lazyios/bin/pip install --no-cache-dir --no-deps /src \
    && /opt/lazyios/bin/pip install --no-cache-dir "textual>=8.2,<9"

ENV PATH="/opt/lazyios/bin:${PATH}" \
    COLORTERM=truecolor
ENV NO_COLOR=
