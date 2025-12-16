#!/bin/bash

# Allow self-registration of organizations at TMForum
curl -X 'POST' http://pap-provider.INTERNAL_IP.nip.io/policy \
    -H 'Content-Type: application/json' \
    -d "$(cat /fiware/policies/allowSelfRegistrationLegalPerson.json)"

# Allow to order at TMForum
curl -X 'POST' http://pap-provider.INTERNAL_IP.nip.io/policy \
    -H 'Content-Type: application/json' \
    -d "$(cat /fiware/policies/allowProductOrder.json)"

# Allow to offer at TMForum for identified Representatives
curl -X 'POST' http://pap-provider.INTERNAL_IP.nip.io/policy \
    -H 'Content-Type: application/json' \
    -d "$(cat /fiware/policies/allowProductOfferingCreation.json)"

# Allow to read offers at TMForum
curl -X 'POST' http://pap-provider.INTERNAL_IP.nip.io/policy \
    -H 'Content-Type: application/json' \
    -d "$(cat /fiware/policies/allowProductOffering.json)"

# Allow creation of product specs
curl -X 'POST' http://pap-provider.INTERNAL_IP.nip.io/policy \
    -H 'Content-Type: application/json' \
    -d "$(cat /fiware/policies/allowProductSpec.json)"
