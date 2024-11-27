#!/usr/bin/env bash

function do_it () {
  local CA_CERTIFICATE_FOLDER
  local LOCAL_CA_FILE_PATH

  local CERT_FILENAME

  local FULL_CA_CERTIFICATES_PATH
  local CA_FILE_PATH

  CA_CERTIFICATE_FOLDER="mtls_proxy_ca"
  LOCAL_CA_FILE_PATH=${1:-_fake_pki/_ca/certificate.pem}

  CERT_FILENAME="ca.crt"

  FULL_CA_CERTIFICATES_PATH="/usr/share/ca-certificates/${CA_CERTIFICATE_FOLDER}"
  CA_FILE_PATH="${FULL_CA_CERTIFICATES_PATH}/${CERT_FILENAME}"

  mkdir "${FULL_CA_CERTIFICATES_PATH}"
  cp "${LOCAL_CA_FILE_PATH}" "${CA_FILE_PATH}"

  echo "${CA_CERTIFICATE_FOLDER}/${CERT_FILENAME}" | tee -a /etc/ca-certificates.conf

  update-ca-certificates
}

do_it "$@"
