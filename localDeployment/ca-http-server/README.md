# CA over HTTP (geen TLS-kip-en-ei)

Kleine nginx + initContainer in namespace `cert-manager` die het bestaande cert-manager secret **`ca-secret`** (veld `tls.crt`) serveert als download **`dsconnector-ca.crt`**.

## Wanneer toepassen

Na de reguliere installatie, zodra dit bestaat:

```bash
kubectl -n cert-manager get secret ca-secret
```

## Handmatig testen

Vanaf de root van de repo (of met `-f` per bestand):

```bash
kubectl apply -k localDeployment/ca-http-server/
```

Wacht tot de pod ready is:

```bash
kubectl -n cert-manager rollout status deployment/dsconnector-ca-server
```

### Download (aanbevolen: NodePort)

Standaard is **NodePort 30090**. Vervang `<INTERNAL_IP>` door het IP van de k3s-node (zelfde als je andere `.nip.io` URLs):

- Startpagina: `http://<INTERNAL_IP>:30090/`
- Direct CA-bestand: `http://<INTERNAL_IP>:30090/dsconnector-ca.crt`

### Download (optioneel: Ingress HTTP)

Pas in `ingress.yaml` de host aan naar `ca.<INTERNAL_IP>.nip.io` en apply opnieuw, of gebruik je bestaande `prepare-native-k3s-server.sh` flow die `127.0.0.1.nip.io` vervangt als je deze manifests onder `k3s/` zou hangen.

- `http://ca.<INTERNAL_IP>.nip.io/`
- `http://ca.<INTERNAL_IP>.nip.io/dsconnector-ca.crt`

## Client: CA vertrouwen (Windows)

1. Download `dsconnector-ca.crt`.
2. Elevated CMD/PowerShell:

```bat
certutil -addstore -f Root dsconnector-ca.crt
```

Herstart de browser. Daarna zouden `https://keycloak-provider....nip.io` en het dashboard zonder cert-warnings moeten werken.

## Verificatie fingerprint (optioneel)

Op de server:

```bash
kubectl -n cert-manager get secret ca-secret -o jsonpath='{.data.tls\.crt}' | base64 -d | openssl x509 -noout -fingerprint -sha256
```

Vergelijk met het geïmporteerde certificaat op de client (Windows: certmgr.msc → Trusted Root → eigenschappen).

## Integratie in `prepare-native-k3s-server.sh`

Na succesvolle handmatige test: voeg `kubectl apply -k ...` toe na `apply_manifests` (of na cert-manager/CA resources beschikbaar zijn), en print de download-URL (NodePort + eventueel ingress host).
