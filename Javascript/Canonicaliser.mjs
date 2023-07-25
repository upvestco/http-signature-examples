// This class is "just" a "library" of all methods that format the signature
// input data in a standardised way, so that we are actually calculating a
// signature of the same input data as the verifier.
// This includes type assertions, which need to be
// much stricter than typical Javascript or Typescript.
export class Canonicaliser {
    // You can just use the lodash library for `Canonicaliser.util`
    // @see https://www.npmjs.com/package/lodash
    util;

    // Keeps an adapter / wrapper for whatever cryptography library
    // is available in the current environment, for example `node:crypto`
    // or https://github.com/kjur/jsrsasign (which is recommended for
    // Postman.)
    // @see https://en.wikipedia.org/wiki/Adapter_pattern
    crypto;

    constructor(util, crypto) {
        // @see https://en.wikipedia.org/wiki/Dependency_injection
        this.util = util;
        this.crypto = crypto;
    }

    canonicaliseAll(
        sig, // This is typically the Signature instance which contains this Canonicaliser.
        {
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
        }
    ) {
        sig.method = this.canonicaliseMethod(method);
        ({ path: sig.path, hasQuery: sig.hasQuery, query: sig.query } = this.canonicaliseURL(url));
        sig.headers = this.canonicaliseHeaders(headers);
        ({ hasBody: sig.hasBody, body: sig.body } = this.canonicaliseBody(body));
        sig.keyId = this.canonicaliseKeyId(keyId);
        sig.signatureKey = this.canonicaliseSignatureKey(signatureKey);
        ({ created: sig.created, dateHeader: sig.dateHeader } = this.canonicaliseCreatedAndDateHeader(created, sig.headers));
        ({ hasExpiresInSeconds: sig.hasExpiresInSeconds, expiresInSeconds: sig.expiresInSeconds } = this.canonicaliseExpiresInSeconds(expiresInSeconds));
        sig.nonce = this.canonicaliseNonce(nonce);
        ({ hasAlgorithmName: sig.hasAlgorithmName, algorithmName: sig.algorithmName } = this.canonicaliseAlgorithmName(algorithmName));
    }

    canonicaliseMethod(method) {
        if (this.util.isString(method)) {
            return method.toUpperCase();
        }
        throw new Error('HTTP method must be a string');
    }

    canonicaliseURL(url) {
        if (url instanceof URL) {
            // According to https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-message-signatures-15#name-query
            // the leading question mark "?" has to be included, which `URL.search` does, but `URLSearchParams.toString()` does not.
            // The `null` default value is a signal to *NOT* include the "@query" component in the Signature Input String.
            const query = url.search ? url.search : null;
            return {
                // According to https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-message-signatures-15#name-path
                // an empty path gets canonicalised as "/". The Node.js v20.4.0 implementation of `URL.pathname` does that,
                // but according to https://developer.mozilla.org/en-US/docs/Web/API/URL/pathname we should expect to get an empty string here.
                path: url.pathname ? url.pathname : '/',

                query,
                hasQuery: !this.util.isNull(query)
            };
        }
        throw new Error('request url must be of type URL');
    }

    canonicaliseHeaders(headers) {
        // TODO canonicalise multiple headers with the same header name.
        if (this.util.isPlainObject(headers)) {
            // lower-case all header names
            headers = Object.fromEntries(Object.entries(headers).map(([name, value]) => ([name.toLowerCase(), value])))
            // TODO reject headers with non-standard header names
            return headers;
        }
        throw new Error('request headers must be a plain object');
    }

    canonicaliseBody(body) {
        if (this.util.isNull(body)) {
            return { hasBody: false, body };
        }
        if (body instanceof Uint8Array) {
            return { hasBody: true, body };
        }
        if (this.util.isPlainObject(body) || this.util.isArray(body)) {
            // Take care of JSON payloads
            // TODO automatically set the `content-type` header to `application/json`.
            const enc = new TextEncoder();
            return { hasBody: true, body: enc.encode(JSON.stringify(body)) };
        }
        if (this.util.isString(body)) {
            // We can not take strings here because we need the byte count for the `content-length` header.
            // @see https://developer.mozilla.org/en-US/docs/Web/API/TextEncoder
            const enc = new TextEncoder();
            return { hasBody: true, body: enc.encode(body) };
        }
        throw new Error('request body must be given as null, string or Uint8Array');
    }

    canonicaliseKeyId(keyId) {
        if (this.util.isString(keyId)) {
            return keyId;
        } else {
            throw new Error('key ID must be be given as a string');
        }
    }

    canonicaliseSignatureKey(signatureKey) {
        // This really depends on the cryptography implementation
        // (For example `node:crypto` versus libraries imported into Postman, etc.)
        // So as a default, do nothing here.
        // TODO Maybe use `util` here. (Which would break the assumption that `util` is just the `lodash` package.)
        return signatureKey;
    }

    canonicaliseCreatedAndDateHeader(created, headers) {

        const getDateWithoutMilliseconds = (...dateValues) => {
            const date = new Date(...dateValues);
            date.setUTCMilliseconds(0); // this effectively rounds *down* to the nearest second
            return date;
        };

        if ('date' in headers) {
            if (this.util.isNull(created)) {
                return { created: getDateWithoutMilliseconds(headers.date), dateHeader: headers.date };
            }
            if (this.util.isDate(created) || this.util.isString(created)) {
                created = getDateWithoutMilliseconds(created);
                if (created.toUTCString() != headers.date) {
                    throw new Error('found mismatching "date" header and "created" timestamp');
                }
                return { created, dateHeader: headers.date };
            }
        } else {
            if (this.util.isNull(created)) {
                created = getDateWithoutMilliseconds();
                return { created, dateHeader: created.toUTCString() };
            }
            if (this.util.isDate(created) || this.util.isString(created)) {
                created = getDateWithoutMilliseconds(created);
                return { created, dateHeader: created.toUTCString() };
            }
        }
        throw new Error('created timestamp must be given as null, a string, or a Date object');
    }

    canonicaliseExpiresInSeconds(expiresInSeconds) {
        if (this.util.isNull(expiresInSeconds)) {
            return { hasExpiresInSeconds: false, expiresInSeconds };
        }
        if (this.util.isInteger(expiresInSeconds) && expiresInSeconds > 0) {
            return { hasExpiresInSeconds: true, expiresInSeconds };
        }
        if (this.util.isString(expiresInSeconds)) {
            expiresInSeconds = parseInt(expiresInSeconds, 10)
            if (expiresInSeconds > 0) {
                return { hasExpiresInSeconds: true, expiresInSeconds };
            }
        }
        throw new Error('expiresInSeconds must be given as a positive integer number, or a base-10 string thereof.');
    }

    canonicaliseNonce(nonce) {
        return this.util.isNull(nonce) ? this.crypto.randomUUID() : String(nonce);
    }

    canonicaliseAlgorithmName(algorithmName) {
        if (this.util.isNull(algorithmName)) {
            return { hasAlgorithmName: false, algorithmName };
        }
        if (this.util.isString(algorithmName)) {
            return { hasAlgorithmName: true, algorithmName };
        }
        throw new Error('algorithmName must be given as either string or null.');
    }
}
