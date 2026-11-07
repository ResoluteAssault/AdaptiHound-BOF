#pragma once
#include "sha1.hpp"

static bool ah_directory_certificate_store = false;

static void ah_certificate_chain(ah_graph &g, ah_buffer &b, ah_object *o) {
    ah_value *certificate = o->values("cACertificate");
    AH_TEXT(&b, "[");
    bool first = true;
    if (certificate) {
        PCCERT_CONTEXT context = CRYPT32$CertCreateCertificateContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, reinterpret_cast<const BYTE *>(certificate->data), static_cast<DWORD>(certificate->size));
        if (context) {
            CERT_CHAIN_PARA parameters = {};
            parameters.cbSize = sizeof(parameters);

            HCERTSTORE store = ah_directory_certificate_store ? CRYPT32$CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, CERT_STORE_CREATE_NEW_FLAG, nullptr) : nullptr;
            if (store) for (ah_object *candidate = g.directory.objects; candidate; candidate = candidate->next) {
                for (ah_value *encoded = candidate->values("cACertificate"); encoded; encoded = encoded->next)
                    CRYPT32$CertAddEncodedCertificateToStore(store, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                        reinterpret_cast<const BYTE *>(encoded->data), static_cast<DWORD>(encoded->size), CERT_STORE_ADD_USE_EXISTING, nullptr);
            }
            const CERT_CHAIN_CONTEXT *chain = nullptr;
            if (CRYPT32$CertGetCertificateChain(nullptr, context, nullptr, store, &parameters, 0, nullptr, &chain) && chain && chain->cChain) {

                PCERT_SIMPLE_CHAIN simple = chain->rgpChain[0];
                if (simple) {
                    for (DWORD j = 0; j < simple->cElement; ++j) {
                        ah_value encoded = {reinterpret_cast<char *>(simple->rgpElement[j]->pCertContext->pbCertEncoded), simple->rgpElement[j]->pCertContext->cbCertEncoded, nullptr};
                        if (!first) { AH_TEXT(&b, ","); } first = false;
                        ah_string(b, ah_thumbprint(g.arena, &encoded));
                    }
                }
            }
            if (chain) CRYPT32$CertFreeCertificateChain(chain);
            if (store) CRYPT32$CertCloseStore(store, 0);
            CRYPT32$CertFreeCertificateContext(context);
        }
    }
    AH_TEXT(&b, "]");
}
