mkdir -p signing
openssl genrsa -out signing/private.pem -3 3072
openssl rsa -in signing/private.pem -outform PEM -pubout -out signing/public.pem

mkdir -p attestation
openssl genrsa -out attestation/private.pem -3 3072
openssl rsa -in attestation/private.pem -outform PEM -pubout -out attestation/public.pem
