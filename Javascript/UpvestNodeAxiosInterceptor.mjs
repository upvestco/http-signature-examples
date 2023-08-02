import buildURL from 'axios/unsafe/helpers/buildURL.js';

import { upvestNodeSign } from './UpvestNodeSigner.mjs';
import { inspect, inspectAxiosError } from './util.mjs';

export class UpvestNodeAxiosInterceptor {
    keyId;
    key;

    constructor(keyId, key) {
        this.keyId = keyId;
        this.key = key;
    }

    interceptAndSignRequest(config) {
        // Arrive at the same parameter serialization as Axios.
        // TODO Write back to config.url and unset config.params, to avoid running buildURL() twice,
        //      and thereby potentially having diverging serializations.
        const axiosUrl = buildURL(config.url, config.params, config.paramsSerializer);
        // @see https://developer.mozilla.org/en-US/docs/Web/API/URL
        // @see https://url.spec.whatwg.org/#api
        const whatwgUrl = new URL(axiosUrl, config.baseURL);

        const defaultHeaders = {
            // These are defaults and can be overridden
            accept: 'application/json'
        };
        if (config.data) {
            // Only provide a default for `content-type` if there is an actual request body.
            // TODO Figure out how to limit this to actual JSON requests only. (Canonicaliser knows, but that runs much later.)
            defaultHeaders['content-type'] = 'application/json';
        }

        const headers = Object.assign(defaultHeaders, config.headers);

        try {
            const { outputHeaders, signatureBase } = upvestNodeSign({
                method: config.method,
                url: whatwgUrl,
                headers,
                body: config.data ? config.data : null,
                keyId: this.keyId,
                signatureKey: this.key,
            });
            // TODO Canonicalise `config.headers` to lower case, so that outputHeaders can override them.
            // TODO Consider throwing an error if `config.headers` contains headers that are supposed to be produced by the signing, but have a different value.
            config.headers = Object.assign(config.headers, outputHeaders);

            // Exposing this for debugging purposes
            config.signatureBase = signatureBase;
        } catch (err) {
            inspect(err);
            throw err;
        }

        // TODO Consider writing the binary body, which was derived during signing, back to config.data,
        //      so we have certainty that we are sending the same body that we signed.

        return config;
    }

    interceptRequestError(error) {
        // TODO Do something meaningful with request error
        inspectAxiosError(error);
        return Promise.reject(error);
    }

    install(axiosInstance) {
        axiosInstance.interceptors.request.use(
            config => this.interceptAndSignRequest(config),
            error => this.interceptRequestError(error)
        ); 
    }
}
