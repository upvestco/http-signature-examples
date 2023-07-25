import { Buffer } from 'node:buffer';
import { createHash, createSign, KeyObject, randomUUID } from 'node:crypto';
import lodash from 'lodash';

import { Canonicaliser } from './Canonicaliser.mjs';
import { Signature } from './Signature.mjs';

export class NodeCanonicaliser extends Canonicaliser {
    canonicaliseBody(body) {
        if (body instanceof Buffer) {
            // Also accept Node's `Buffer` objects.
            // TODO Maybe figure out a way to convert to `Uint8Array`?
            return { hasBody: true, body };
        }
        return super.canonicaliseBody(body);
    }

    canonicaliseSignatureKey(signatureKey) {
        if (signatureKey instanceof KeyObject) {
            return signatureKey;
        }
        throw new Error('signature key should be given as a node:crypto KeyObject');
    }

}

export class NodeCryptoProvider {
    getSha256HashAsBase64(body) {
        return createHash('sha256').update(body).digest('base64');
    }

    getSha512HashAsBase64(body) {
        return createHash('sha512').update(body).digest('base64');
    }

    getSignatureAsBase64(messageToSign, signatureKey) {
        return createSign('SHA512')
            .update(messageToSign)
            .end()
            .sign(signatureKey)
            .toString('base64');
    }

    randomUUID() {
        return randomUUID();
    }
}

const ignorableHeaderPrefixes = [
    // INTERNAL NOTE: Copied from `ignoreHeadersWithPrefix` in */sign/domain.go
    'cf-',
    'cdn-',
    'cookie',
    'x-',
    'priority',
    'upvest-signature',
    'sec-',
];

const hasIgnorableHeaderPrefix = headerName => {
    const lowerCaseHeaderName = headerName.toLowerCase();
    return ignorableHeaderPrefixes.some(prefix => lowerCaseHeaderName.startsWith(prefix));
}

export function upvestNodeSign({
    method,
    url,
    headers,
    body = null,
    keyId,
    signatureKey,
    created = null,
    expiresInSeconds = 5,
    nonce = null,
    algorithmName = null,
}) {
    const headersToSign = Object.fromEntries(Object.entries(headers).filter(([name]) => !hasIgnorableHeaderPrefix(name)))

    const crypto = new NodeCryptoProvider();
    const canonicaliser = new Canonicaliser(lodash, crypto);
    const sig = new Signature(canonicaliser, crypto);
    const outputHeaders = sig.sign({
        method,
        url,
        headers: headersToSign,
        body,
        keyId,
        signatureKey,
        created,
        expiresInSeconds,
        nonce,
        algorithmName,
    });

    // This is a mandatory fixed value for the Upvest API.
    // It selects the version of the HTTP message signature standard draft.
    // @see https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-message-signatures-15
    // NOTE This header is excluded from being covered by the signature itself.
    const mandatoryVersionSelectHeader = { 'upvest-signature-version': '15' };
    return Object.assign(outputHeaders, mandatoryVersionSelectHeader);
}
