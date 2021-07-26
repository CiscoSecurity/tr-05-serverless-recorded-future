FROM alpine:3.14 AS builder

ENV PIP_IGNORE_INSTALLED 1
ENV PIPENV_VENV_IN_PROJECT 1

WORKDIR /app

# install required packages to build app
RUN apk update && apk add --no-cache \
    musl-dev \
    openssl-dev \
    gcc \
    libffi-dev \
    py3-pip \
    python3-dev

# copy required project files
COPY code/Pipfile code/Pipfile.lock ./

# do the Python dependencies
RUN set -ex && pip install --no-cache-dir --upgrade pipenv && \
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

COPY --from=builder --chown=$NON_ROOT:$NON_ROOT /app/.venv/lib/ $PYROOT/lib/
COPY --from=builder --chown=$NON_ROOT:$NON_ROOT /app/.venv/bin/ $PYROOT/bin/

COPY code /app
COPY scripts /

# install required packages to run app
RUN apk update && apk add --no-cache \
    uwsgi-python3 \
    uwsgi-http \
    uwsgi-syslog \
    supervisor \
    syslog-ng \
    git

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
