/*
 * Copyright © 2024 Upvest GmbH <support@upvest.co>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package co.upvest.client;

import com.google.gson.JsonParser;
import com.google.gson.reflect.TypeToken;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.slf4j.Logger;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class UpvestClientTest {

    private static final String UPVEST_API_VERSION = "1";
    private static final String UPVEST_SIGNATURE_VERSION = "15";
    private static final String SIGNATURE_ID = "sig1";
    private final Logger logger = org.slf4j.LoggerFactory.getLogger(UpvestClientTest.class);
    private SigningKey signatureKey;

    private String serverUrl;
    private String clientId;
    private String clientSecret;
    private String clientScope;

    private String accessToken;

    @BeforeAll
    void setUp() throws IOException, InterruptedException {
        readProperties();
        getAuthToken();
    }

    private void getAuthToken() throws IOException, InterruptedException {

        var authRequestBody = getAuthRequestBody();

        /*
         * We create an object for the signature input. This object will be used to sign the request.
         * The signature input object contains the URL, the content type, the API version, the request body, and the accept header.
         * The reason they are passed explicitly, rather than just passing the request object, is to make the signing process independent
         * of any specific HTTP client library.
         */
        var signatureComponents = new SignatureComponentsAuth(URI.create(serverUrl + "/auth/token"),
                "application/json",
                UPVEST_API_VERSION,
                authRequestBody,
                "application/x-www-form-urlencoded");

        var signedData = SigningUtility.signAuthRequest(signatureKey, signatureComponents);

        try (HttpClient httpClient = HttpClient.newHttpClient()) {

            var request = HttpRequest.newBuilder()
                    .uri(signatureComponents.url())
                    .version(HttpClient.Version.HTTP_1_1)
                    .header("Signature-Input", SIGNATURE_ID + "=" + signedData.signatureParams())
                    .header("Signature", SIGNATURE_ID + "=:" + signedData.signature() + ":")
                    .header("Content-Type", signatureComponents.contentType())
                    .header("Accept", signatureComponents.accept())
                    .header("Upvest-Signature-Version", UPVEST_SIGNATURE_VERSION)
                    .header("Content-Digest", signedData.contentDigest())
                    .POST(HttpRequest.BodyPublishers.ofString(signatureComponents.bodyContent()))
                    .build();

            var mapType = new TypeToken<Map<String, String>>() {
            };

            logger.debug("request = {}", request);
            for (var header : request.headers().map().entrySet()) {
                logger.debug("header = {}", header);
            }

            var response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            logger.debug("response = {}", response);
            logger.debug("response body = {}", response.body());

            var json = JsonParser.parseString(response.body()).getAsJsonObject();
            assertTrue(json.isJsonObject());
            assertNotNull(json.get("access_token"));
            accessToken = json.get("access_token").getAsString();
            logger.debug("authToken = {}", accessToken);
        }
    }

    private String getAuthRequestBody() {
        /*
         * The doesn't really have much to do with the signing. Here we are
         * building the request body for the POST request to get the access token.
         */
        var authRequestFormFields = new HashMap<String, String>();
        authRequestFormFields.put("grant_type", "client_credentials");
        authRequestFormFields.put("scope", clientScope);
        authRequestFormFields.put("client_id", clientId);
        authRequestFormFields.put("client_secret", clientSecret);
        return SigningUtility.getFormDataAsString(authRequestFormFields);
    }


    private void readProperties() {
        try {
            var properties = ConfigReader.readProperties();

            signatureKey = KeyUtility.getSignatureKey(
                    properties.getProperty("UPVEST_API_HTTP_SIGN_PRIVATE_KEY_FILE"),
                    properties.getProperty("UPVEST_API_HTTP_SIGN_PRIVATE_KEY_PASSPHRASE"),
                    properties.getProperty("UPVEST_API_KEY_ID"));

            serverUrl = properties.getProperty("UPVEST_URL");

            clientId = properties.getProperty("UPVEST_API_CLIENT_ID");
            clientSecret = properties.getProperty("UPVEST_API_CLIENT_SECRET");
            clientScope = properties.getProperty("UPVEST_API_CLIENT_SCOPE");

        } catch (IOException ex) {
            logger.error("Failed to read property or key file", ex);
            throw new RuntimeException("Failed to read property or key file", ex);
        }
    }


    @Test
    void getUsers() throws IOException, InterruptedException {

        var getRequestComponents = new SignatureComponentsGet(URI.create(serverUrl + "/users?limit=10"),
                "application/json",
                UPVEST_API_VERSION,
                accessToken,
                clientId);

        var signedData = SigningUtility.signGetRequest(signatureKey, getRequestComponents);

        try (HttpClient httpClient = HttpClient.newHttpClient()) {
            var request = HttpRequest.newBuilder()
                    .uri(getRequestComponents.url())
                    .version(HttpClient.Version.HTTP_1_1)
                    .header("Signature-Input", SIGNATURE_ID + "=" + signedData.signatureParams())
                    .header("Authorization", "Bearer " + getRequestComponents.accessToken())
                    .header("Signature", SIGNATURE_ID + "=:" + signedData.signature() + ":")
                    .header("Accept", getRequestComponents.accept())
                    .header("Upvest-Signature-Version", UPVEST_SIGNATURE_VERSION)
                    .header("Upvest-Api-Version", UPVEST_API_VERSION)
                    .header("Upvest-Client-Id", getRequestComponents.upvestClientId())
                    .GET()
                    .build();


            logger.debug("request = {}", request);
            for (var header : request.headers().map().entrySet()) {
                logger.debug("header = {}", header);
            }

            var response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());


            logger.debug("response = {}", response);
            logger.debug("response body = {}", response.body());
            // We don't really check the returned data. As long as we get a 200 status code, we are good.
            assertEquals(200, response.statusCode());
        }
    }

    @Test
    void getCreateUser() throws IOException, InterruptedException {

        var createUserBody = getCreateUserBody();

        var idempotencyKey = UUID.randomUUID();

        var postRequestComponents = new SignatureComponentsPost(URI.create(serverUrl + "/users"),
                "application/json",
                UPVEST_API_VERSION,
                accessToken,
                clientId,
                createUserBody,
                "application/json");

        var signedData = SigningUtility.signPostRequest(signatureKey, postRequestComponents);

        try (HttpClient httpClient = HttpClient.newHttpClient()) {

            var request = HttpRequest.newBuilder()
                    .uri(postRequestComponents.url())
                    .version(HttpClient.Version.HTTP_1_1)
                    .header("Signature-Input", SIGNATURE_ID + "=" + signedData.signatureParams())
                    .header("Authorization", "Bearer " + postRequestComponents.accessToken())
                    .header("Signature", SIGNATURE_ID + "=:" + signedData.signature() + ":")
                    .header("Content-Type", postRequestComponents.contentType())
                    .header("Accept", postRequestComponents.accept())
                    .header("Upvest-Api-Version", UPVEST_API_VERSION)
                    .header("Upvest-Client-Id", postRequestComponents.upvestClientId())
                    .header("Upvest-Signature-Version", UPVEST_SIGNATURE_VERSION)
                    .header("Content-Digest", signedData.contentDigest())
                    .header("Idempotency-Key", idempotencyKey.toString())
                    .POST(HttpRequest.BodyPublishers.ofString(postRequestComponents.bodyContent()))
                    .build();

            var mapType = new TypeToken<Map<String, String>>() {
            };

            logger.debug("request = {}", request);
            for (var header : request.headers().map().entrySet()) {
                logger.debug("header = {}", header);
            }

            var response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            logger.debug("response = {}", response);
            logger.debug("response body = {}", response.body());

            // We don't really check the returned data. As long as we get a 200 status code, we are good.
            assertEquals(200, response.statusCode());

        }
    }

    private String getCreateUserBody() {
        var user = JsonParser.parseString("""
                {
                        'first_name': 'Peter',
                        'last_name': 'Miller',
                        'email': 'miller@example.com',
                        'birth_date': '1989-11-09',
                        'birth_city': 'Munich',
                        'birth_country': 'DE',
                        'nationalities': ['DE'],
                        'address': {
                            'address_line1': 'Unter den Linden',
                            'address_line2': '12a',
                            'postcode': '10117',
                            'city': 'Berlin',
                            'country': 'DE'
                        },
                        'terms_and_conditions': {
                            'consent_document_id': '62814307-f14b-40af-bc66-5942a549a759',
                            'confirmed_at': '2020-02-03T17:14:46Z'
                        },
                        'data_privacy_and_sharing_agreement': {
                            'consent_document_id': 'dd42b6a9-d04d-4dd2-8c3b-36386eaa843a',
                            'confirmed_at': '2021-02-03T17:14:46Z'
                        },
                        'fatca': {
                            'status': False,
                            'confirmed_at': '2020-02-03T17:14:46Z'
                        }
                    }
                """).getAsJsonObject();
        logger.debug("User: \n{}",user.toString());
        return user.toString();
    }

}
