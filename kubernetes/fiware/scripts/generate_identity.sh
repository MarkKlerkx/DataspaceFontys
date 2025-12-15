#!/bin/bash

# ==========================================
# CONFIGURATION
# ==========================================
DOMAIN_NAME="mp-operations.org"        # <--- CHANGE DOMAIN HERE
IDENTITY_DIR="/fiware/provider-identity"
YAML_FILE="/fiware/provider/provider.yaml"              # Path to your provider.yaml
TOOL_URL="https://github.com/wistefan/did-helper/releases/download/0.1.1/did-helper"
PASSWORD="test"                        # Keystore password

# Ensure directory exists
mkdir -p "$IDENTITY_DIR"

echo "=============================================="
echo "   FIWARE Identity & Config Generator"
echo "   Domain: $DOMAIN_NAME"
echo "=============================================="

# --- Step 0: Check/Download DID Helper Tool ---
echo "--- Step 0: Checking for DID Helper Tool ---"

if [ -f "$IDENTITY_DIR/did-helper" ]; then
    echo "✅ did-helper found in $IDENTITY_DIR"
else
    echo "⬇️  did-helper not found, downloading..."
    if ! command -v wget &> /dev/null; then
        echo "❌ Error: 'wget' is not installed. Please install it first."
        exit 1
    fi
    
    wget -q -O "$IDENTITY_DIR/did-helper" "$TOOL_URL"
    if [ $? -eq 0 ]; then
        chmod +x "$IDENTITY_DIR/did-helper"
        echo "✅ did-helper downloaded and made executable."
    else
        echo "❌ Error downloading did-helper."
        exit 1
    fi
fi

# --- Step 1: Generate OpenSSL Keys ---
echo "--- Step 1: Generating OpenSSL Keys ---"

# 1. Private Key (Prime256v1 / P-256)
openssl ecparam -name prime256v1 -genkey -noout -out "$IDENTITY_DIR/private-key.pem"

# 2. Public Key
openssl ec -in "$IDENTITY_DIR/private-key.pem" -pubout -out "$IDENTITY_DIR/public-key.pem" 2>/dev/null

# 3. Self-Signed Certificate (Uses DOMAIN_NAME)
openssl req -new -x509 -key "$IDENTITY_DIR/private-key.pem" \
    -out "$IDENTITY_DIR/cert.pem" -days 3600 \
    -subj "/CN=$DOMAIN_NAME"

# 4. Export to Keystore (PFX)
openssl pkcs12 -export -inkey "$IDENTITY_DIR/private-key.pem" \
    -in "$IDENTITY_DIR/cert.pem" -out "$IDENTITY_DIR/cert.pfx" \
    -name didPrivateKey -passout pass:$PASSWORD

echo "✅ Keys generated in $IDENTITY_DIR for $DOMAIN_NAME"

# --- Step 2: Calculate X & Y Coordinates ---
echo "--- Step 2: Calculating X & Y Coordinates ---"

PYTHON_SCRIPT=$(cat <<END
import sys, re, base64, binascii, subprocess

def to_base64url(hex_str):
    try:
        b = binascii.unhexlify(hex_str)
        return base64.urlsafe_b64encode(b).decode('utf-8').rstrip('=')
    except Exception:
        return ""

try:
    cmd = ["openssl", "ec", "-in", "$IDENTITY_DIR/private-key.pem", "-text", "-noout"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    output = result.stdout.replace(":", "").replace("\n", "").replace(" ", "")

    match = re.search(r"pub(.*?)ASN1", output)
    if not match: 
        match = re.search(r"pub(.*?)Field", output)
    
    if match:
        raw_hex = match.group(1)
        if raw_hex.startswith("04"):
            raw_hex = raw_hex[2:]
            
        x_hex = raw_hex[:64]
        y_hex = raw_hex[64:128]
        
        print(f"{to_base64url(x_hex)} {to_base64url(y_hex)}")
    else:
        sys.exit(1)
except Exception:
    sys.exit(1)
END
)

read X_COORD Y_COORD <<< $(python3 -c "$PYTHON_SCRIPT")

if [ -z "$X_COORD" ] || [ -z "$Y_COORD" ]; then
    echo "❌ Error: Could not extract coordinates."
    exit 1
fi

echo "✅ Coordinates calculated:"
echo "   X: $X_COORD"
echo "   Y: $Y_COORD"

# --- Step 3: Update Provider.yaml ---
echo "--- Step 3: Updating YAML File ---"

if [ -f "$YAML_FILE" ]; then
    cp "$YAML_FILE" "$YAML_FILE.bak"
    sed -i "s|PLACEHOLDER_X_COORD|$X_COORD|g" "$YAML_FILE"
    sed -i "s|PLACEHOLDER_Y_COORD|$Y_COORD|g" "$YAML_FILE"
    echo "✅ $YAML_FILE updated with new keys."
else
    echo "⚠️ Warning: $YAML_FILE not found."
fi

# --- Step 4: Generate did.json ---
echo "--- Step 4: Generating did.json (via did-helper) ---"

"$IDENTITY_DIR/did-helper" \
    -keystorePath "$IDENTITY_DIR/cert.pfx" \
    -keystorePassword=$PASSWORD \
    -outputFile "$IDENTITY_DIR/did.json" > /dev/null 2>&1

if [ -f "$IDENTITY_DIR/did.json" ]; then
    echo "✅ did.json created at $IDENTITY_DIR/did.json"
else
    echo "❌ Error: Could not create did.json."
    exit 1
fi

echo "=============================================="
echo "   DONE! Follow these next steps:"
echo "=============================================="
echo "1. Update your Kubernetes Secrets:"
echo "   kubectl delete secret provider-identity signing-key cert-chain tls-secret -n provider --ignore-not-found"
echo "   kubectl create secret generic provider-identity --from-file=cert.pfx=$IDENTITY_DIR/cert.pfx -n provider"
echo "   kubectl create secret generic signing-key --from-file=client.key.pem=$IDENTITY_DIR/private-key.pem -n provider"
echo "   kubectl create secret generic cert-chain --from-file=client-chain-bundle.cert.pem=$IDENTITY_DIR/cert.pem -n provider"
echo "   kubectl create secret tls tls-secret --cert=$IDENTITY_DIR/cert.pem --key=$IDENTITY_DIR/private-key.pem -n provider"
echo ""
echo "2. Install the Helm chart:"
echo "   helm install provider-dsc data-space-connector/data-space-connector -f $YAML_FILE --namespace provider"
