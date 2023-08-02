export class Signature {

    // Keeps a reference to the Canonicaliser to be used.
    canonicaliser;

    // Keeps an adapter / wrapper for whatever cryptography library
    // is available in the current environment, for example `node:crypto`
    // or https://github.com/kjur/jsrsasign (which is recommended for
    // Postman.)
    // @see https://en.wikipedia.org/wiki/Adapter_pattern
    crypto;

    // These fields get populated by a Canonicaliser instance.
    method;
    path;
    hasQuery;
    query;
    headers;
    hasBody;
    body;
    keyId;
    signatureKey;
    dateHeader;
    created;
    hasExpiresInSeconds;
    expiresInSeconds;
    nonce;
    hasAlgorithmName;
    algorithmName;

    // The signature components are [key, value] pairs but must also have a repeatable order.
    components = new Map();
    orderedComponentIds = [];

    constructor(canonicaliser, crypto) {
        // @see https://en.wikipedia.org/wiki/Dependency_injection
        this.canonicaliser = canonicaliser;
        this.crypto = crypto;
    }

    addComponent(id, value) {
        if (this.hasComponent(id)) {
            throw new Error(`unable to add duplicate signature component "${id}"`)
        }
        this.orderedComponentIds.push(id);
        this.components.set(id, String(value));
    }

    hasComponent(id) {
        return this.components.has(id);
    }

    getComponent(id) {
        return this.components.get(id);
    }

    // @see https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-message-signatures-15#name-signature-parameters
    getSignatureParams({ algorithmName, keyId, createdTimestamp, expiresTimestamp, nonce }) {
        const coveredComponentsList = this.orderedComponentIds.map(id => `"${id}"`).join(' ');

        const signatureParams = [];
        signatureParams.push(`(${coveredComponentsList})`);
        if (algorithmName) {
            signatureParams.push(`alg="${algorithmName}"`);
        }
        signatureParams.push(`keyid="${keyId}"`);
        signatureParams.push(`created=${createdTimestamp}`); // no double quotes because it's an integer
        if (expiresTimestamp) {
            signatureParams.push(`expires=${expiresTimestamp}`); // no double quotes because it's an integer
        }
        signatureParams.push(`nonce="${nonce}"`);

        return signatureParams.join(';');
    }

    formatSignatureBasePart(id, value) {
        return `"${id}": ${value}`;
    }

    // @see https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-message-signatures-15#name-creating-the-signature-base
    getSignatureParamsAndBase({ algorithmName, keyId, createdTimestamp, expiresTimestamp, nonce }) {
        const signatureBaseParts = this.orderedComponentIds.map(id => this.formatSignatureBasePart(id, this.getComponent(id)));

        const signatureParams = this.getSignatureParams({ algorithmName, keyId, createdTimestamp, expiresTimestamp, nonce });
        signatureBaseParts.push(this.formatSignatureBasePart('@signature-params', signatureParams));

        const signatureBase = signatureBaseParts.join('\n');

        return {
            signatureParams,
            signatureBase,
        };
    }

    // @see https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-message-signatures-15#name-message-content
    // @see https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-digest-headers-10
    getDigestHeaderNameAndValue(body) {
        const digestHeaderName = 'content-digest';
        const digestBase64 = this.crypto.getSha512HashAsBase64(body);
        const digestHeaderValue = `sha-512=:${digestBase64}:`;
        return { digestHeaderName, digestHeaderValue };
    }

    // See `Canonicaliser.canonicaliseAll()` for which properties go inside `input`.
    sign(inputs) {
        // This stores the canonicalised inputs in properties on `this` Signature object.
        this.canonicaliser.canonicaliseAll(this, inputs);

        const outputHeaders = {};

        this.addComponent('@method', this.method);
        this.addComponent('@path', this.path);

        if (this.hasQuery) {
            this.addComponent('@query', this.query);
        }

        for (const [headerName, headerValue] of Object.entries(this.headers)) {
            this.addComponent(headerName, headerValue);
        }
        if (!('date' in this.headers)) {
            outputHeaders['date'] = this.dateHeader;
            this.addComponent('date', this.dateHeader);
        }

        if (this.hasBody) {
            const contentLengthHeaderValue = String(this.body.length);
            if (this.headers['content-length'] && this.headers['content-length'] != contentLengthHeaderValue) {
                throw new Error(`found "content-length" header with value "${this.headers['content-length']}", but calculated "${contentLengthHeaderValue}`)
            }
            this.addComponent('content-length', contentLengthHeaderValue);
            outputHeaders['content-length'] = contentLengthHeaderValue;

            const { digestHeaderName, digestHeaderValue } = this.getDigestHeaderNameAndValue(this.body);
            if (this.headers[digestHeaderName] && this.headers[digestHeaderName] != String(digestHeaderValue)) {
                throw new Error(`found "digest" header with value "${this.headers[digestHeaderName]}", but calculated "${digestHeaderValue}`)
            }
            this.addComponent(digestHeaderName, digestHeaderValue);
            outputHeaders[digestHeaderName] = digestHeaderValue;
        }

        // TODO Maybe move this to Canonicaliser.
        const createdTimestamp = Math.floor(this.created.getTime() / 1000);
        const expiresTimestamp = this.hasExpiresInSeconds ? createdTimestamp + this.expiresInSeconds : null;

        const { signatureParams, signatureBase } = this.getSignatureParamsAndBase({ algorithmName: this.algorithmName, keyId: this.keyId, createdTimestamp, expiresTimestamp, nonce: this.nonce });
        outputHeaders['signature-input'] = `sig1=${signatureParams}`;

        const signature = this.crypto.getSignatureAsBase64(signatureBase, this.signatureKey);
        outputHeaders['signature'] = `sig1=:${signature}:`;

        return { outputHeaders, signatureBase };
    }
}
