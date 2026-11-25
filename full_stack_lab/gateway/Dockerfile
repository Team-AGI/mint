FROM zricethezav/gitleaks:v8.30.1 AS secrets
# Native engines are compiled here; the runtime image gets only the shared objects.
FROM golang:1.24.13-bookworm AS native-go
WORKDIR /src/gitleaks
COPY native/gitleaks/ ./
RUN CGO_ENABLED=1 go build -trimpath -buildmode=c-shared -o /out/libmcpgw_gitleaks.so .
# The PC setup programs: one fixed executable per platform, the employee's kit is appended at download.
COPY native/setup/ /src/setup/
RUN cd /src/setup && CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "-s -w -H windowsgui" -o /out/setup/windows-amd64.exe .     && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o /out/setup/linux-amd64 .
FROM python:3.12-slim AS native-c
RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev libpcre2-dev \
    && rm -rf /var/lib/apt/lists/*
COPY native/textscan/textscan.c /src/
# PCRE2 is linked statically, so the runtime image needs no extra package.
RUN mkdir /out && gcc -O2 -fPIC -shared -Wall -Wextra -Werror -Wno-unused-parameter -Wno-missing-field-initializers \
      $(python3-config --includes) /src/textscan.c -o /out/mcpgw_textscan$(python3-config --extension-suffix) \
      -Wl,-Bstatic -lpcre2-32 -Wl,-Bdynamic
FROM python:3.12-slim AS native-rust
# fast-anything ports (.fast/ports): functions verified against the Python original, built as abi3 extensions.
# The Python function stays and runs when the extension is missing or FAST_ANYTHING_DISABLE=1.
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates gcc libc6-dev     && rm -rf /var/lib/apt/lists/*     && curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain 1.100.0
COPY .fast/ports/ /src/ports/
# The port's own config targets the local CPU; the image may run on another one.
ENV RUSTFLAGS="-C opt-level=3"
RUN mkdir /out && for d in /src/ports/*/; do       (cd "$d" && /root/.cargo/bin/cargo build --release --locked -q) || exit 1;       for so in "$d"target/release/lib*.so; do n="${so##*/lib}"; cp "$so" "/out/${n%.so}.abi3.so"; done;     done
FROM python:3.12-slim
COPY windows-python.json prepare-windows-python.py /tmp/windows-python/
RUN python /tmp/windows-python/prepare-windows-python.py /tmp/windows-python/windows-python.json /opt/windows-python \
    && rm -r /tmp/windows-python
COPY --from=secrets /usr/bin/gitleaks /usr/local/bin/gitleaks
COPY --from=native-go /out/libmcpgw_gitleaks.so /usr/local/lib/
COPY --from=native-go /out/setup/ /opt/mcp-setup/
COPY --from=native-c /out/ /usr/local/lib/python3.12/site-packages/
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && useradd --uid 10001 --create-home appuser \
    && mkdir -p /runtime /reports /registry-runtime /disposal \
    && chown -R appuser:appuser /app /runtime /reports /registry-runtime /disposal
COPY --chown=appuser:appuser app ./app
COPY --from=native-rust /out/ ./.fast/lib/
ARG MCP_BUILD_REVISION=unknown
ENV MCP_BUILD_REVISION=$MCP_BUILD_REVISION
LABEL org.opencontainers.image.revision=$MCP_BUILD_REVISION
USER appuser
EXPOSE 8080 8081
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
