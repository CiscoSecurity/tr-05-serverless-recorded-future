FROM alpine:3.14
LABEL maintainer="Ian Redden <iaredden@cisco.com>"

ENV NON_ROOT ciscosec
ENV PIP_IGNORE_INSTALLED 1
ENV PIPENV_PIPFILE app/Pipfile
ENV PIPENV_SYSTEM 1

# create non-root user
RUN addgroup --system $NON_ROOT && \
    adduser -S -G $NON_ROOT $NON_ROOT

# install required packages
RUN apk update && apk add --no-cache \
    musl-dev \
    openssl-dev \
    gcc \
    py3-configobj \
    supervisor \
    git \
    libffi-dev \
    uwsgi-python3 \
    uwsgi-http \
    jq \
    syslog-ng \
    uwsgi-syslog \
    py3-pip \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

# copy required project files
COPY code /app
COPY scripts /

# do the Python dependencies
RUN set -ex && pip install --upgrade pipenv && \
    pipenv install --deploy

# add required permissions to non-root user
RUN mv /uwsgi.ini /etc/uwsgi && \
    addgroup $NON_ROOT uwsgi && \
    addgroup uwsgi $NON_ROOT && \
    chmod +x /*.sh && \
	chown -R $NON_ROOT:$NON_ROOT /var/log && \
    chown -R $NON_ROOT:$NON_ROOT /run && \
    chown -R $NON_ROOT:$NON_ROOT /usr/sbin/uwsgi && \
    chown -R $NON_ROOT:$NON_ROOT /etc/uwsgi

# set non-root user for docker daemon
USER $NON_ROOT

# entrypoint
ENTRYPOINT ["/entrypoint.sh"]
CMD ["/start.sh"]
