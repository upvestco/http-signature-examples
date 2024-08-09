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

public class SignatureComponentsAuth extends SignatureComponents {
    public final static String httpMethod = "POST";
    private final static Logger logger = org.slf4j.LoggerFactory.getLogger(SignatureComponentsAuth.class);
    public final String bodyContent;
    public final String contentType;

    public SignatureComponentsAuth(URI url, String accept, String apiVersion, String bodyContent, String contentType) {
        super(url, accept, apiVersion);
        Objects.requireNonNull(bodyContent, "bodyContent must not be null");
        Objects.requireNonNull(contentType, "contentType must not be null");
        this.bodyContent = bodyContent;
        this.contentType = contentType;
    }


    public SignatureAuth sign(SignatureKey key) {
        try {
            var contentDigest = SigningUtil.getSHA512Digest(bodyContent);

            // It has to be a LinkedHashMap to keep the order of the fields
            var signatureFields = new LinkedHashMap<String, String>();
            signatureFields.put("\"content-type\"", contentType);
            signatureFields.put("\"content-length\"", String.valueOf(bodyContent.length()));
            signatureFields.put("\"accept\"", accept);
            signatureFields.put("\"@method\"", httpMethod);
            signatureFields.put("\"@path\"", url.getPath());
            signatureFields.put("\"content-digest\"", contentDigest);

            var signatureParams = SigningUtil.createSignatureParametersString(signatureFields, key);
            signatureFields.put("\"@signature-params\"", signatureParams);

            var signature = SigningUtil.sign(signatureFields, key);
            logger.debug("Signature: {}", signature);
            return new SignatureAuth(contentDigest, signatureParams, signature);
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException ex) {
            logger.error(ex.getMessage(), ex);
            throw new RuntimeException(ex);
        }
    }

    public record SignatureAuth(String contentDigest, String signatureParams, String signature) {
    }

}
