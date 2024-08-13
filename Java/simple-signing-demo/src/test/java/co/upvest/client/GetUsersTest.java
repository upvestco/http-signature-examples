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

import com.google.gson.Gson;
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

import static org.junit.jupiter.api.Assertions.assertEquals;


@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class GetUsersTest {

    private static final String UPVEST_API_VERSION = "1";
    private static final String UPVEST_SIGNATURE_VERSION = "15";
    private static final String SIGNATURE_ID = "sig1";
    private final Logger logger = org.slf4j.LoggerFactory.getLogger(GetUsersTest.class);
    private SignatureKey signatureKey;

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

        var signedData = signatureComponents.sign(signatureKey);

        try (HttpClient httpClient = HttpClient.newHttpClient()) {

            var request = HttpRequest.newBuilder()
                    .uri(signatureComponents.url)
                    .version(HttpClient.Version.HTTP_1_1)
                    .header("Signature-Input", SIGNATURE_ID + "=" + signedData.signatureParams())
                    .header("Signature", SIGNATURE_ID + "=:" + signedData.signature() + ":")
                    .header("Content-Type", signatureComponents.contentType)
                    .header("Accept", signatureComponents.accept)
                    .header("Upvest-Signature-Version", UPVEST_SIGNATURE_VERSION)
                    .header("Content-Digest", signedData.contentDigest())
                    .POST(HttpRequest.BodyPublishers.ofString(signatureComponents.bodyContent))
                    .build();

            var gson = new Gson();
            var mapType = new TypeToken<Map<String, String>>() {
            };

            logger.debug("request = {}", request);
            for (var header : request.headers().map().entrySet()) {
                logger.debug("header = {}", header);
            }

            var response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            logger.debug("response = {}", response);
            logger.debug("response body = {}", response.body());

            var bodyAsMap = gson.fromJson(response.body(), mapType);

            logger.debug("authToken = {}", bodyAsMap.get("access_token"));
            accessToken = bodyAsMap.get("access_token");
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
        return SigningUtil.getFormDataAsString(authRequestFormFields);
    }


    private void readProperties() {
        try {
            var properties = ConfigReader.readProperties();

            signatureKey = SigningUtil.getSignatureKey(
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

        var authParam = new SignatureComponentsGet(URI.create(serverUrl + "/users?limit=10"),
                "application/json",
                UPVEST_API_VERSION,
                accessToken,
                clientId);

        var signedData = authParam.sign(signatureKey);

        try (HttpClient httpClient = HttpClient.newHttpClient()) {
            var request = HttpRequest.newBuilder()
                    .uri(authParam.url)
                    .version(HttpClient.Version.HTTP_1_1)
                    .header("Signature-Input", SIGNATURE_ID + "=" + signedData.signatureParams())
                    .header("Authorization", "Bearer " + authParam.accessToken)
                    .header("Signature", SIGNATURE_ID + "=:" + signedData.signature() + ":")
                    .header("Accept", authParam.accept)
                    .header("Upvest-Signature-Version", "15")
                    .header("Upvest-Api-Version", UPVEST_API_VERSION)
                    .header("Upvest-Client-Id", authParam.upvestClientId)
                    .GET()
                    .build();


            logger.debug("request = {}", request);
            for (var header : request.headers().map().entrySet()) {
                logger.debug("header = {}", header);
            }

            var response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

            // We don't really check the returned data. As long as we get a 200 status code, we are good.
            assertEquals(200, response.statusCode());

            logger.debug("response = {}", response);
            logger.debug("response body = {}", response.body());
        }
    }
}
