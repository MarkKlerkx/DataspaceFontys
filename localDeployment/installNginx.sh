#!/bin/bash
# ============================================================
# FIWARE Data Space Connector - Final Universal Bridge
# ============================================================

set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVER_IP=$(ip route get 8.8.8.8 | awk '{for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}')

echo "==> Server IP gedetecteerd: $SERVER_IP"

# Mapstructuur voor Nginx Proxy Manager
mkdir -p "$SCRIPT_DIR/npm/data/nginx/custom"
mkdir -p "$SCRIPT_DIR/npm/letsencrypt"
sudo chown -R "$USER:$USER" "$SCRIPT_DIR/npm"

# ------------------------------------------------------------
# 1. Dummy SSL Certificaten genereren (voor poort 443 start)
# ------------------------------------------------------------
if [ ! -f "$SCRIPT_DIR/npm/data/nginx/dummycert.pem" ]; then
    echo "==> Dummy certificaten genereren voor HTTPS start..."
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout "$SCRIPT_DIR/npm/data/nginx/dummykey.pem" \
        -out "$SCRIPT_DIR/npm/data/nginx/dummycert.pem" \
        -subj "/CN=*.${SERVER_IP}.nip.io"
fi

# ------------------------------------------------------------
# 2. Python script voor de Wildcard & Redirect Configuratie
# ------------------------------------------------------------
PYTHON_SCRIPT=$(mktemp /tmp/gen_final_bridge_XXXXXX.py)

cat > "$PYTHON_SCRIPT" << 'PYEOF'
import sys
server_ip = sys.argv[1]
out_conf  = sys.argv[2]
out_comp  = sys.argv[3]
ip_esc    = server_ip.replace(".", r"\.")

def get_config():
    # De logica voor het doorsturen en corrigeren van URL's
    proxy_logic =  "        set $upstream_host \"$service.127.0.0.1.nip.io\";\n"
    proxy_logic += f"        set $external_host \"$service.{server_ip}.nip.io\";\n\n"
    
    # Tunnel naar de K3s HTTPS poort
    proxy_logic += "        proxy_pass https://host.docker.internal:8443;\n"
    proxy_logic += "        proxy_ssl_verify off;\n"
    proxy_logic += "        proxy_ssl_server_name on;\n\n"

    # CORRECTIE VAN REDIRECTS (Voorkomt de 127.0.0.1 redirect)
    proxy_logic += "        proxy_redirect https://$upstream_host/ https://$external_host/;\n"
    proxy_logic += "        proxy_redirect http://$upstream_host/ https://$external_host/;\n\n"
    
    # Headers voor Traefik en App compatibiliteit
    proxy_logic += "        proxy_set_header Host $upstream_host;\n"
    proxy_logic += "        proxy_set_header X-Real-IP $remote_addr;\n"
    proxy_logic += "        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n"
    proxy_logic += "        proxy_set_header X-Forwarded-Proto https;\n\n"
    
    # WebSocket & Buffer optimalisatie
    proxy_logic += "        proxy_http_version 1.1;\n"
    proxy_logic += "        proxy_set_header Upgrade $http_upgrade;\n"
    proxy_logic += "        proxy_set_header Connection \"upgrade\";\n"
    proxy_logic += "        proxy_read_timeout 3600s;\n"
    proxy_logic += "        proxy_buffer_size 128k;\n"
    proxy_logic += "        proxy_buffers 4 256k;\n"

    # Server blok voor HTTP en HTTPS
    c =  "server {\n"
    c += "    listen 80;\n"
    c += "    listen 443 ssl;\n"
    c += f"    server_name ~^(?P<service>.+)\\.{ip_esc}\\.nip\\.io$;\n\n"
    
    # Gebruik de gegenereerde dummy certificaten
    c += "    ssl_certificate /data/nginx/dummycert.pem;\n"
    c += "    ssl_certificate_key /data/nginx/dummykey.pem;\n\n"

    c += "    location / {\n"
    c += proxy_logic
    c += "    }\n"
    c += "}\n"
    return c

def get_compose():
    return f"""services:
  dataspace-gateway:
    image: 'jc21/nginx-proxy-manager:latest'
    container_name: dataspace-gateway
    restart: unless-stopped
    ports:
      - '80:80'
      - '81:81'
      - '443:443'
    volumes:
      - ./npm/data:/data
      - ./npm/letsencrypt:/etc/letsencrypt
    extra_hosts:
      - "host.docker.internal:host-gateway"
"""

with open(out_conf, "w") as f: f.write(get_config())
with open(out_comp, "w") as f: f.write(get_compose())
PYEOF

python3 "$PYTHON_SCRIPT" "$SERVER_IP" "$SCRIPT_DIR/npm/data/nginx/custom/http.conf" "$SCRIPT_DIR/docker-compose.yml"
rm -f "$PYTHON_SCRIPT"

# ------------------------------------------------------------
# 3. Herstarten & Afronding
# ------------------------------------------------------------
echo "==> Nginx Proxy Manager container (her)starten..."
docker compose -f "$SCRIPT_DIR/docker-compose.yml" down || true
docker compose -f "$SCRIPT_DIR/docker-compose.yml" up -d

echo "==> Wachten op initialisatie (10s)..."
sleep 10
docker exec dataspace-gateway nginx -t

echo "============================================================"
echo " DE BRIDGE IS VOLLEDIG OPERATIONEEL!"
echo "============================================================"
echo " Keycloak: http://keycloak-provider.$SERVER_IP.nip.io/admin/"
echo " Scorpio : http://scorpio-provider.$SERVER_IP.nip.io/ngsi-ld/v1/types"
echo " Headlamp: http://headlamp.$SERVER_IP.nip.io"
echo ""
echo " Let op: Bij de overstap naar HTTPS krijg je een waarschuwing."
echo " Klik op 'Geavanceerd' -> 'Doorgaan' om de GUI te openen."
echo "============================================================"