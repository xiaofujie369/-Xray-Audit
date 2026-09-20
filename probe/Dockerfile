FROM python:3.12-slim
WORKDIR /app
COPY agent ./agent
COPY probe ./probe
RUN useradd --uid 10001 --create-home probe
USER 10001
CMD ["python", "-m", "probe.probe_agent", "--config", "/data/config.json"]
