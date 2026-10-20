ARG FIREFOX_IMAGE=oxibelt/firefox-webdriver:158.0.1-geckodriver-0.37.1
FROM ${FIREFOX_IMAGE}

USER root

ARG WPT_REVISION=ece2d7fdc436d4b9a3856877163b07ec15c05354
ARG CHROME_VERSION=155.0.8059.84
ARG CHROME_SHA256=cf0f049892dea22e6a6db26d47ed0d7776b7158edcbec4634086633df8bafcbc
ARG CHROMEDRIVER_SHA256=4fe2433044363e5233d642e70fa50278b471bda08032d922402c8bd7c6d743fd

RUN apt-get update \
  && apt-get install --yes --no-install-recommends \
    build-essential git iptables passwd python3 python3-dev python3-venv \
    python3-pip unzip \
  && rm -rf /var/lib/apt/lists/* \
  && /usr/sbin/groupadd --gid 10002 wpt \
  && /usr/sbin/useradd --uid 10002 --gid 10002 --create-home --shell /bin/bash wpt

RUN set -eux; \
  mkdir -p /opt/wpt; \
  git -C /opt/wpt init -q; \
  git -C /opt/wpt -c protocol.version=2 fetch \
    --depth 1 --filter=blob:none --no-tags \
    https://github.com/web-platform-tests/wpt.git "${WPT_REVISION}"; \
  git -C /opt/wpt checkout --detach FETCH_HEAD; \
  test "$(git -C /opt/wpt rev-parse HEAD)" = "${WPT_REVISION}"; \
  test -z "$(git -C /opt/wpt status --porcelain)"; \
  printf '%s\n' "${WPT_REVISION}" > /opt/wpt/.source-revision; \
  rm -rf /opt/wpt/.git; \
  chown -R 10002:10002 /opt/wpt

RUN set -eux; \
  curl --fail --location --retry 3 --retry-all-errors \
    --output /tmp/chrome.zip \
    "https://storage.googleapis.com/chrome-for-testing-public/${CHROME_VERSION}/linux64/chrome-linux64.zip"; \
  echo "${CHROME_SHA256}  /tmp/chrome.zip" | sha256sum --check --strict; \
  unzip -q /tmp/chrome.zip -d /opt; \
  mv /opt/chrome-linux64 /opt/chrome; \
  curl --fail --location --retry 3 --retry-all-errors \
    --output /tmp/chromedriver.zip \
    "https://storage.googleapis.com/chrome-for-testing-public/${CHROME_VERSION}/linux64/chromedriver-linux64.zip"; \
  echo "${CHROMEDRIVER_SHA256}  /tmp/chromedriver.zip" | sha256sum --check --strict; \
  unzip -q /tmp/chromedriver.zip -d /opt; \
  mv /opt/chromedriver-linux64 /opt/chromedriver; \
  rm /tmp/chrome.zip /tmp/chromedriver.zip; \
  /opt/chrome/chrome --version | grep --fixed-strings -- "Google Chrome for Testing ${CHROME_VERSION}"; \
  /opt/chromedriver/chromedriver --version | grep --fixed-strings -- "ChromeDriver ${CHROME_VERSION} "; \
  test "$(/opt/firefox/firefox --version)" = "Mozilla Firefox 158.0.1"

WORKDIR /opt/wpt

# Install the pinned WPT runner dependencies when building the image. The
# browser runs can then reuse the same venv without resolving packages at test
# startup, and missing native build prerequisites fail during image creation.
RUN python3 -m venv /opt/wpt/_venv3 \
  && /opt/wpt/_venv3/bin/pip install --disable-pip-version-check --prefer-binary \
    -r tools/wpt/requirements.txt \
    -r tools/webtransport/requirements.txt \
    -r tools/wptrunner/requirements.txt \
    -r tools/wptrunner/requirements_chromium.txt \
    -r tools/wptrunner/requirements_firefox.txt \
  && chown -R 10002:10002 /opt/wpt/_venv3

# WPT prompts for the unrelated OpenH264 plugin on Firefox startup when this
# directory is absent. WebTransport tests do not use it; keep the run offline.
RUN mkdir -p /opt/wpt/_venv3/browsers/stable/gmp-gmpopenh264 \
  && chown -R 10002:10002 /opt/wpt/_venv3/browsers

# WPT otherwise fetches Firefox test preferences at each run. The pinned
# Firefox 156 source profile is small, so verify it during image creation and
# keep browser runs independent of GitHub availability or rate limits.
ARG FIREFOX_SOURCE_REV=3bf8f468258c2181f455e23d4ffcd6acb8f4cdb1
COPY firefox-profiles.sha256 /opt/wpt/firefox-profiles.sha256
RUN set -eux; \
  mkdir -p /opt/wpt/firefox-profiles; \
  while read -r expected relative; do \
    mkdir -p "/opt/wpt/firefox-profiles/$(dirname "$relative")"; \
    curl --fail --location --retry 3 --retry-all-errors \
      --header 'Accept: application/vnd.github.raw+json' \
      --output "/opt/wpt/firefox-profiles/$relative" \
      "https://api.github.com/repos/mozilla-firefox/firefox/contents/testing/profiles/$relative?ref=${FIREFOX_SOURCE_REV}"; \
    echo "$expected  /opt/wpt/firefox-profiles/$relative" | sha256sum --check --strict; \
  done < /opt/wpt/firefox-profiles.sha256; \
  chown -R 10002:10002 /opt/wpt/firefox-profiles

ENTRYPOINT ["/bin/sleep", "infinity"]
