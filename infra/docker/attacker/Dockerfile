# Attacker container: Kali rolling + a focused web-pentest toolset.
# Built by the host Docker daemon (which has internet); at runtime the container sits on
# labnet (no egress). The orchestrator reaches it via `docker exec`.
FROM kalilinux/kali-rolling:latest

ENV DEBIAN_FRONTEND=noninteractive

# Keep this list aligned with the profile's safety.allow where it makes sense.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      nmap \
      curl \
      wget \
      netcat-traditional \
      sqlmap \
      nikto \
      whatweb \
      gobuster \
      ffuf \
      hydra \
      dnsutils \
      iproute2 \
      iputils-ping \
      ca-certificates \
      python3 \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /root
CMD ["sleep", "infinity"]
