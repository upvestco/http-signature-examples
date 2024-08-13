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


import org.slf4j.Logger;

import java.net.URI;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.LinkedHashMap;
import java.util.Objects;

public class SignatureComponentsGet extends SignatureComponents {

    public final static String httpMethod = "GET";
    private final static Logger logger = org.slf4j.LoggerFactory.getLogger(SignatureComponentsAuth.class);
    public final String accessToken;
    public final String upvestClientId;

    public SignatureComponentsGet(URI url, String accept, String apiVersion, String accessToken, String upvestClientId) {
        super(url, accept, apiVersion);
        Objects.requireNonNull(accessToken);
        Objects.requireNonNull(upvestClientId);
        this.accessToken = accessToken;
        this.upvestClientId = upvestClientId;
    }

    public SignatureGet sign(SignatureKey key) {

        // It has to be a LinkedHashMap to keep the order of the fields
        var signatureFields = new LinkedHashMap<String, String>();
        signatureFields.put("\"upvest-client-id\"", upvestClientId);
        signatureFields.put("\"authorization\"", "Bearer " + accessToken);
        signatureFields.put("\"upvest-api-version\"", apiVersion);
        signatureFields.put("\"accept\"", accept);
        signatureFields.put("\"@method\"", SignatureComponentsGet.httpMethod);
        signatureFields.put("\"@path\"", url.getPath());
        signatureFields.put("\"@query\"", "?" + url.getRawQuery());

        var signatureParams = SigningUtil.createSignatureParametersString(signatureFields, key);
        signatureFields.put("\"@signature-params\"", signatureParams);
        try {
            var signature = SigningUtil.sign(signatureFields, key);
            logger.debug("Signature: {}", signature);
            return new SignatureGet(signatureParams, signature);

        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException ex) {
            logger.error(ex.getMessage(), ex);
            throw new RuntimeException(ex);
        }
    }

    public record SignatureGet(String signatureParams, String signature) {
    }
}
