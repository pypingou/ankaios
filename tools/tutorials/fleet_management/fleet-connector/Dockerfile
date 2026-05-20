FROM python:3.12-slim-bookworm

WORKDIR /usr/src/app

# Copy local SDK wheel with signed YAML support
COPY ankaios_sdk-1.0.1-py3-none-any.whl ./

# Install local SDK wheel and other dependencies
RUN pip install --no-cache-dir ./ankaios_sdk-1.0.1-py3-none-any.whl paho-mqtt==2.1.0

COPY fleet-connector.py ./

CMD [ "python", "-u", "./fleet-connector.py" ]
