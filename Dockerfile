FROM alpine:3.14 AS builder
LABEL maintainer="Ian Redden <iaredden@cisco.com>"

ENV NON_ROOT ciscosec
ENV PIPENV_PIPFILE code/Pipfile
ENV PIPENV_SYSTEM 1
ENV PYROOT /pyroot
ENV PIP_IGNORE_INSTALLED 1
ENV PATH=$PYROOT/bin:$PATH \
    PYTHONUSERBASE=$PYROOT

WORKDIR /app

# install required packages
RUN apk update && apk add --no-cache \
    musl-dev \
    openssl-dev \
    gcc \
    libffi-dev \
    py3-pip \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

# copy required project files
COPY code ./code
COPY scripts ./scripts

# do the Python dependencies
RUN set -ex && pip install --no-cache-dir --upgrade pipenv && \
    PIP_USER=1 \
    pipenv install --deploy

FROM alpine:3.14

ENV NON_ROOT ciscosec
ENV PYROOT /pyroot
ENV PATH=$PYROOT/bin:$PATH \
    PYTHONPATH=$PYROOT/lib/python:$PATH \
    PYTHONUSERBASE=$PYROOT

# create non-root user
RUN addgroup --system $NON_ROOT && \
    adduser -S \
    -h $PYROOT \
    -G $NON_ROOT $NON_ROOT

COPY --from=builder --chown=$NON_ROOT:$NON_ROOT $PYROOT/lib/ $PYROOT/lib/
COPY --from=builder --chown=$NON_ROOT:$NON_ROOT $PYROOT/bin/ $PYROOT/bin/
COPY --from=builder --chown=$NON_ROOT:$NON_ROOT /app/code /app
COPY --from=builder --chown=$NON_ROOT:$NON_ROOT /app/scripts /

RUN apk update && apk add --no-cache \
    uwsgi-python3 \
    uwsgi-http \
    uwsgi-syslog \
    supervisor \
    syslog-ng \
    git \
    py3-pip

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
