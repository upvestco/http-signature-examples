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

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Random;

/**
 * Utility class for signing requests.
 */
public final class SigningUtility {

    private static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(SigningUtility.class);
    private static final String NONCE_ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    private static final int NONCE_LENGTH = 16;
    private static final Random RANDOM = new SecureRandom();

    private SigningUtility() {
        // no instances, just static methods
    }

    /**
     * Converts a map of form data to a URL-encoded string.
     *
     * @param formData the form data
     * @return the URL-encoded form data
     */
    static String getFormDataAsString(Map<String, String> formData) {
        StringBuilder formBodyBuilder = new StringBuilder();
        for (Map.Entry<String, String> entry : formData.entrySet()) {
            if (!formBodyBuilder.isEmpty()) {
                formBodyBuilder.append("&");
            }
            formBodyBuilder.append(URLEncoder.encode(entry.getKey(), StandardCharsets.UTF_8));
            formBodyBuilder.append("=");
            formBodyBuilder.append(URLEncoder.encode(entry.getValue(), StandardCharsets.UTF_8));
        }
        return formBodyBuilder.toString();
    }

    /**
     * Signs the given fields with the given key.
     *
     * @param signatureFields the fields to sign
     * @param key             the key to sign with
     * @return the signature
     * @throws NoSuchAlgorithmException if the algorithm is not available
     * @throws InvalidKeyException      if the key is invalid
     * @throws SignatureException       if the signature cannot be created
     */
    static String sign(LinkedHashMap<String, String> signatureFields, SigningKey key) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        var signingStringBuilder = new StringBuilder();
        for (Map.Entry<String, String> signingField : signatureFields.entrySet()) {
            signingStringBuilder
                    .append(signingField.getKey())
                    .append(": ")
                    .append(signingField.getValue())
                    .append("\n");
        }
        String signatureBase = signingStringBuilder.toString().trim();
        logger.debug("\nSignature Base:\n'{}'", signatureBase);

        Signature sig = Signature.getInstance("SHA512withECDSA");
        sig.initSign(key.key());
        sig.update(signatureBase.getBytes(StandardCharsets.UTF_8));
        var signedBytes = sig.sign();
        var signature = Base64.getEncoder().encodeToString(signedBytes);
        logger.debug("Signature: {}", signature);
        return signature;
    }

    /**
     * Generates a random nonce.
     *
     * @return the nonce
     */
    public static String generateNonce() {
        StringBuilder nonce = new StringBuilder();
        for (int i = 0; i < NONCE_LENGTH; i++) {
            int index = RANDOM.nextInt(NONCE_ALPHABET.length());
            nonce.append(NONCE_ALPHABET.charAt(index));
        }
        return nonce.toString();
    }

    /**
     * Generates a SHA-512 digest of the given input.
     *
     * @param input the input
     * @return the digest
     * @throws NoSuchAlgorithmException if the algorithm is not available
     */
    public static String getSHA512Digest(String input) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-512");
        byte[] hashBytes = digest.digest(
                input.getBytes(StandardCharsets.UTF_8));
        return "sha-512=:" + Base64.getEncoder().encodeToString(hashBytes) + ":";
    }

    /**
     * Creates the signature parameters string.
     *
     * @param signatureFields the fields to sign
     * @param key             the key to sign with
     * @return the signature parameters string
     */
    static String createSignatureParametersString(LinkedHashMap<String, String> signatureFields, SigningKey key) {
        var nonce = generateNonce();
        var now = LocalDateTime.now(ZoneOffset.UTC);
        var expires = now.plusMinutes(1);

        var signatureParamsBuilder = new StringBuilder();
        signatureParamsBuilder.append("(");
        for (Map.Entry<String, String> signingField : signatureFields.entrySet()) {
            signatureParamsBuilder.append(signingField.getKey());
            signatureParamsBuilder.append(" ");
        }
        // now we have to remove the last space...
        signatureParamsBuilder.deleteCharAt(signatureParamsBuilder.length() - 1)
                .append(")")
                .append(";keyid=\"")
                .append(key.keyId())
                .append("\";created=")
                .append(now.toEpochSecond(ZoneOffset.UTC))
                .append(";nonce=\"")
                .append(nonce)
                .append("\";expires=")
                .append(expires.toEpochSecond(ZoneOffset.UTC));

        return signatureParamsBuilder.toString();
    }


    /**
     * Signs a POST request.
     *
     * @param key                 the key to sign with
     * @param signatureComponents the signature components
     * @return the signature
     */
    public static SignaturePost signPostRequest(SigningKey key, SignatureComponentsPost signatureComponents) {
        try {
            var contentDigest = SigningUtility.getSHA512Digest(signatureComponents.bodyContent());

            // It has to be a LinkedHashMap to keep the order of the fields
            var signatureFields = new LinkedHashMap<String, String>();
            signatureFields.put("\"upvest-client-id\"", signatureComponents.upvestClientId());
            signatureFields.put("\"authorization\"", "Bearer " + signatureComponents.accessToken());
            signatureFields.put("\"upvest-api-version\"", signatureComponents.apiVersion());
            signatureFields.put("\"content-type\"", signatureComponents.contentType());
            signatureFields.put("\"content-length\"", String.valueOf(signatureComponents.bodyContent().length()));
            signatureFields.put("\"accept\"", signatureComponents.accept());
            signatureFields.put("\"@method\"", signatureComponents.httpMethod());
            signatureFields.put("\"@path\"", signatureComponents.url().getPath());
            signatureFields.put("\"content-digest\"", contentDigest);

            var signatureParams = SigningUtility.createSignatureParametersString(signatureFields, key);
            signatureFields.put("\"@signature-params\"", signatureParams);

            var signature = SigningUtility.sign(signatureFields, key);
            logger.debug("Signature: {}", signature);
            return new SignaturePost(contentDigest, signatureParams, signature);
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException ex) {
            logger.error(ex.getMessage(), ex);
            throw new RuntimeException(ex);
        }
    }


    /**
     * Signs a GET request.
     *
     * @param key                 the key to sign with
     * @param signatureComponents the signature components
     * @return the signature
     */
    public static SignatureGet signGetRequest(SigningKey key, SignatureComponentsGet signatureComponents) {

        // It has to be a LinkedHashMap to keep the order of the fields
        var signatureFields = new LinkedHashMap<String, String>();
        signatureFields.put("\"upvest-client-id\"", signatureComponents.upvestClientId());
        signatureFields.put("\"authorization\"", "Bearer " + signatureComponents.accessToken());
        signatureFields.put("\"upvest-api-version\"", signatureComponents.apiVersion());
        signatureFields.put("\"accept\"", signatureComponents.accept());
        signatureFields.put("\"@method\"", signatureComponents.httpMethod());
        signatureFields.put("\"@path\"", signatureComponents.url().getPath());
        signatureFields.put("\"@query\"", "?" + signatureComponents.url().getRawQuery());

        var signatureParams = SigningUtility.createSignatureParametersString(signatureFields, key);
        signatureFields.put("\"@signature-params\"", signatureParams);
        try {
            var signature = SigningUtility.sign(signatureFields, key);
            logger.debug("Signature: {}", signature);
            return new SignatureGet(signatureParams, signature);

        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException ex) {
            logger.error(ex.getMessage(), ex);
            throw new RuntimeException(ex);
        }
    }

    /**
     * Signs an authentication request.
     *
     * @param key                 the key to sign with
     * @param signatureComponents the signature components
     * @return the signature
     */
    public static SignaturePost signAuthRequest(SigningKey key, SignatureComponentsAuth signatureComponents) {
        try {
            var contentDigest = SigningUtility.getSHA512Digest(signatureComponents.bodyContent());

            // It has to be a LinkedHashMap to keep the order of the fields
            var signatureFields = new LinkedHashMap<String, String>();
            signatureFields.put("\"content-type\"", signatureComponents.contentType());
            signatureFields.put("\"content-length\"", String.valueOf(signatureComponents.bodyContent().length()));
            signatureFields.put("\"accept\"", signatureComponents.accept());
            signatureFields.put("\"@method\"", signatureComponents.httpMethod());
            signatureFields.put("\"@path\"", signatureComponents.url().getPath());
            signatureFields.put("\"content-digest\"", contentDigest);

            var signatureParams = SigningUtility.createSignatureParametersString(signatureFields, key);
            signatureFields.put("\"@signature-params\"", signatureParams);

            var signature = SigningUtility.sign(signatureFields, key);
            logger.debug("Signature: {}", signature);
            return new SignaturePost(contentDigest, signatureParams, signature);
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException ex) {
            logger.error(ex.getMessage(), ex);
            throw new RuntimeException(ex);
        }
    }

}
