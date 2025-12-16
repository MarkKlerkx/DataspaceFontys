#!/bin/bash

# Allow read-access to the Rainbow Catalog API
curl -X 'POST' http://pap-provider.INTERNAL_IP.nip.io/policy \
    -H 'Content-Type: application/json' \
    -d "$(cat /fiware/policies/allowCatalogRead.json)"


# Allow self-registration of organizations at TMForum
curl -X 'POST' http://pap-provider.INTERNAL_IP.nip.io/policy \
    -H 'Content-Type: application/json' \
    -d "$(cat /fiware/policies/allowSelfRegistration.json)"


# Allow to order at TMForum
curl -X 'POST' http://pap-provider.INTERNAL_IP.nip.io/policy \
    -H 'Content-Type: application/json' \
    -d "$(cat /fiware/policies/allowProductOrder.json)"

# Allow operators to read uptime-reports
curl -X 'POST' http://pap-provider.INTERNAL_IP.nip.io/policy \
    -H 'Content-Type: application/json' \
    -d "$(cat /fiware/policies/uptimeReport.json)"

# Allow operators to request data transfers at Rainbow
curl -X 'POST' http://pap-provider.INTERNAL_IP.nip.io/policy \
    -H 'Content-Type: application/json' \
    -d "$(cat /fiware/policies/transferRequest.json)"

# Allow the consumer to read its agreements
curl -X 'POST' http://pap-provider.INTERNAL_IP.nip.io/policy \
    -H 'Content-Type: application/json' \
    -d "$(cat /fiware/policies/allowTMFAgreementRead.json)"
