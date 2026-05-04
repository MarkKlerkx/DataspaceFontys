# Ingress URL Portal (klikbare links)

Kleine “portal” die **Kubernetes Ingress resources** uitleest en daar klikbare URLs (incl. `http://` of `https://`) van maakt, plus een paar gebruikersacties.

- **Bron**: `kubectl get ingress -A -o json`
- **Sortering**:
  - Keycloaks bovenaan (hosts met `keycloak`)
  - Provider dashboard daarna (`dashboard-provider.*`) + hint `Login: admin / test`
- **Extra**:
  - CA-certificaat download: `/dsconnector-ca.crt` (komt uit `cert-manager/ca-secret`)
  - Headlamp: link + token ophalen via knop
- **Output**: portal op poort 80 via NodePort **30091**

## Installeren (handmatig op de k3s server)

```bash
kubectl apply -k localDeployment/ingress-url-portal/
kubectl -n kube-system rollout status deploy/ingress-url-portal
```

## Openen

Vervang `<INTERNAL_IP>` door je k3s node IP:

- `http://<INTERNAL_IP>:30091/`

## Voorwaarden

- `cert-manager` + `ca-secret` moet bestaan (uit jullie standaard deployment).
- Headlamp is optioneel; als `my-headlamp` service bestaat in `kube-system`, verschijnt de Headlamp kaart automatisch.

## Verwijderen

```bash
kubectl delete -k localDeployment/ingress-url-portal/
```

