ARG DEBIAN_IMAGE=docker.io/library/debian:trixie-slim@sha256:abc9cb88a5587630d7f915f47b23b0668fe250fbfc6457aa4d52b534c1bbf73f

FROM ${DEBIAN_IMAGE} AS fetch

ARG FIREFOX_VERSION=154.0
ARG FIREFOX_SHA256=7665cd49ab13417270748325838e565136adbc76d41bbd76fb24d15a0cc7792b
ARG GECKODRIVER_VERSION=0.37.1
ARG GECKODRIVER_SHA256=e815130ea95983e162ae91843b48d3a3ce991735635fce83a647afde21e09f7e

RUN apt-get update \
  && apt-get install --yes --no-install-recommends ca-certificates curl xz-utils \
  && rm -rf /var/lib/apt/lists/*

RUN set -eux; \
  curl --fail --location --retry 3 --retry-all-errors \
    --output /tmp/firefox.tar.xz \
    "https://archive.mozilla.org/pub/firefox/releases/${FIREFOX_VERSION}/linux-x86_64/en-US/firefox-${FIREFOX_VERSION}.tar.xz"; \
  echo "${FIREFOX_SHA256}  /tmp/firefox.tar.xz" | sha256sum --check --strict; \
  mkdir -p /opt/firefox; \
  tar --extract --xz --file /tmp/firefox.tar.xz --strip-components 1 --directory /opt/firefox

RUN set -eux; \
  curl --fail --location --retry 3 --retry-all-errors \
    --output /tmp/geckodriver.tar.gz \
    "https://github.com/mozilla/geckodriver/releases/download/v${GECKODRIVER_VERSION}/geckodriver-v${GECKODRIVER_VERSION}-linux64.tar.gz"; \
  echo "${GECKODRIVER_SHA256}  /tmp/geckodriver.tar.gz" | sha256sum --check --strict; \
  tar --extract --gzip --file /tmp/geckodriver.tar.gz --directory /tmp geckodriver

FROM ${DEBIAN_IMAGE}

ARG FIREFOX_VERSION=154.0
ARG GECKODRIVER_VERSION=0.37.1

RUN apt-get update \
  && apt-get install --yes --no-install-recommends \
    ca-certificates \
    curl \
    fonts-liberation \
    fonts-noto-color-emoji \
    libasound2t64 \
    libatk-bridge2.0-0t64 \
    libatk1.0-0t64 \
    libcairo-gobject2 \
    libcairo2 \
    libcups2t64 \
    libdbus-1-3 \
    libdbus-glib-1-2 \
    libdrm2 \
    libfontconfig1 \
    libfreetype6 \
    libgbm1 \
    libglib2.0-0t64 \
    libgtk-3-0t64 \
    libnspr4 \
    libnss3 \
    libnss3-tools \
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    libpci3 \
    libx11-6 \
    libx11-xcb1 \
    libxcb-shm0 \
    libxcb1 \
    libxcomposite1 \
    libxcursor1 \
    libxdamage1 \
    libxext6 \
    libxfixes3 \
    libxi6 \
    libxkbcommon0 \
    libxrandr2 \
    libxrender1 \
    libxshmfence1 \
    libxss1 \
    libxt6t64 \
    libxtst6 \
    zip \
  && rm -rf /var/lib/apt/lists/* \
  && groupadd --gid 10001 webdriver \
  && useradd --uid 10001 --gid 10001 --create-home --shell /usr/sbin/nologin webdriver

COPY --from=fetch /opt/firefox /opt/firefox
COPY --from=fetch /tmp/geckodriver /usr/local/bin/geckodriver

RUN chmod 0755 /usr/local/bin/geckodriver \
  && mkdir -p /tmp/oxibelt-firefox-logs \
  && chown 10001:10001 /tmp/oxibelt-firefox-logs \
  && test "$(id -u webdriver)" = "10001" \
  && test "$(id -g webdriver)" = "10001" \
  && test "$(/opt/firefox/firefox --version)" = "Mozilla Firefox ${FIREFOX_VERSION}" \
  && /usr/local/bin/geckodriver --version | grep --fixed-strings -- "geckodriver ${GECKODRIVER_VERSION} " \
  && command -v certutil \
  && command -v zip \
  && command -v curl

LABEL org.opencontainers.image.source="https://github.com/OxiBelt/OxiBelt" \
  org.opencontainers.image.title="OxiBelt Firefox WebDriver test helper" \
  org.opencontainers.image.version="${FIREFOX_VERSION}-geckodriver-${GECKODRIVER_VERSION}"

ENV HOME=/home/webdriver \
  MOZ_HEADLESS=1 \
  PATH=/opt/firefox:/usr/local/bin:/usr/bin:/bin

USER 10001:10001

EXPOSE 4444

ENTRYPOINT ["/usr/local/bin/geckodriver"]
CMD ["--host", "127.0.0.1", "--port", "4444"]
