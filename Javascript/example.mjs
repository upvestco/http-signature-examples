import { randomUUID } from 'node:crypto';

import axios from 'axios';

import settings from './settings.mjs';
import { UpvestNodeAxiosInterceptor } from './UpvestNodeAxiosInterceptor.mjs';
import { NodeKeyLoader } from './NodeKeyLoader.mjs';
import { inspect, inspectAxiosResponse, inspectAxiosError } from './util.mjs';

const printSignatureBase = (response) => {
    if ('signatureBase' in response.config) {
        console.log('signatureBase ==');
        console.log(response.config.signatureBase);
        console.log('base64(signatureBase) ==');
        console.log(btoa(response.config.signatureBase));
    }
}

const getAuthToken = async (api) => {
    try {
        const headers = {
            'content-type': 'application/x-www-form-urlencoded',
        };
        const body = new URLSearchParams({
            'client_id': settings.CLIENT_ID,
            'client_secret': settings.CLIENT_SECRET,
            'grant_type': 'client_credentials',
            'scope': 'users:admin'
        });
        const response = await api.post('auth/token', body.toString(), { headers });
        printSignatureBase(response);
        inspectAxiosResponse(response);
        return response.data;
    } catch (error) {
        inspectAxiosError(error);
    }
}

const withAuthHeader = (otherHeaders, authToken) => {
    return Object.assign(otherHeaders, {
        'authorization': `Bearer ${authToken.access_token}`,
    });
}

const listUsers = async (api, authToken) => {
    try {
        const params = {
            'offset': 0,
            'limit': 2,
        };
        const response = await api.get('users', { headers: withAuthHeader({}, authToken), params });
        printSignatureBase(response);
        inspectAxiosResponse(response);
        return response.data;
    } catch (error) {
        inspectAxiosError(error);
    }
}

const createUser = async (api, authToken) => {
    try {
        const headers = {
            'content-type': 'application/json',
            'idempotency-key': randomUUID(),
        };
        const body = {
            "first_name": "Marcel",
            "last_name": "Schwarz",
            "email": "marcel@example.com",
            "birth_date": "1992-06-16",
            "birth_city": "Mannheim",
            "birth_country": "DE",
            "nationalities": ["DE"],
            "address": {
                "address_line1": "Unter den Linden",
                "address_line2": "12a",
                "postcode": "10117",
                "city": "Berlin",
                "country": "DE"
            },
            "terms_and_conditions": {
                "consent_document_id": "62814307-f14b-40af-bc66-5942a549a759",
                "confirmed_at": "2020-02-03T17:14:46Z"
            },
            "data_privacy_and_sharing_agreement": {
                "consent_document_id": "dd42b6a9-d04d-4dd2-8c3b-36386eaa843a",
                "confirmed_at": "2021-02-03T17:14:46Z"
            },
            "fatca": {
                "status": false,
                "confirmed_at": "2020-02-03T17:14:46Z"
            }
        };
        const response = await api.post('users', body, { headers: withAuthHeader(headers, authToken) });
        printSignatureBase(response);
        inspectAxiosResponse(response);
        return response.data;
    } catch (error) {
        inspectAxiosError(error);
    }
}

const deleteUser = async (api, authToken, userId) => {
    try {
        const headers = {
            'idempotency-key': randomUUID(),
        };
        const response = await api.delete(`users/${userId}`, { headers: withAuthHeader(headers, authToken) });
        printSignatureBase(response);
        inspectAxiosResponse(response);
        return response.data;
    } catch (error) {
        inspectAxiosError(error);
    }
}

const printAsHeading = msg => {
    console.log();
    console.log('#'.repeat(msg.length + 4));
    console.log(`# ${msg.toUpperCase()} #`);
    console.log('#'.repeat(msg.length + 4));
}

const main = async () => {
    const upvestApi = axios.create({
        baseURL: settings.SERVER_BASE_URL,
        timeout: 10000,
        validateStatus: null, // do not treat non-2xx as errors.
        headers: {
            'accept': 'application/json',
            'upvest-client-id': settings.CLIENT_ID,
            'upvest-api-version': '1',
        }
    });

    const key = await (new NodeKeyLoader()).load(settings.PRIVATE_KEY_FILE, settings.PRIVATE_KEY_PASSWORD);
    const interceptor = new UpvestNodeAxiosInterceptor(settings.KEY_ID, key);
    interceptor.install(upvestApi);

    printAsHeading('get auth token');
    const authToken = await getAuthToken(upvestApi);

    printAsHeading('list users');
    const users = await listUsers(upvestApi, authToken);

    printAsHeading('create user');
    const newUser = await createUser(upvestApi, authToken);

    printAsHeading('delete user');
    const deleteResult = await deleteUser(upvestApi, authToken, newUser.id);
};

main();
