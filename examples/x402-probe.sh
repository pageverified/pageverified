#!/bin/sh
# Ask a per-call route for its x402 offer. Nothing is paid and no tool runs:
# a POST with no API key and no PAYMENT-SIGNATURE answers 402 with the offer.
#
# The offer is the PAYMENT-REQUIRED header: base64 of an x402 version 2 JSON object
# (USDC on Base, scheme "exact"). The body repeats the price in plain JSON.
curl -s -X POST https://pageverified.com/api/v1/x402/inspect -D - -o /dev/null \
  | tr -d '\r' \
  | grep -i '^payment-required:' | cut -d' ' -f2- \
  | base64 -d
echo
