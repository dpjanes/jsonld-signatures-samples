[ ! -d ppk ] && mkdir ppk
openssl genrsa -out ppk/private.pem
openssl req -new -x509 -key ppk/private.pem -out ppk/cert.pem -days 365 -subj "/C=CA/CN=example.com"
openssl rsa -in ppk/private.pem -pubout -out ppk/public.pem
cat ppk/public.pem ppk/cert.pem  >> ppk/combined.pem
