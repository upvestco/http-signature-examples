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

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.bc.BcPEMDecryptorProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.pkcs.jcajce.JcePKCSPBEInputDecryptorProviderBuilder;

import java.io.FileReader;
import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Random;

public final class SigningUtil {

    private static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(SigningUtil.class);
    private static final String NONCE_ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    private static final int NONCE_LENGTH = 16;
    private static final Random RANDOM = new SecureRandom();

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private SigningUtil() {
        // no instances, just static methods
    }

    public static SignatureKey getSignatureKey(String keyFileName, String keyPassphrase, String keyId) {
        try (PEMParser pemParser = new PEMParser(new FileReader(keyFileName))) {
            PrivateKeyInfo pki;
            Object o = pemParser.readObject();
            if (o instanceof PKCS8EncryptedPrivateKeyInfo epki) {
                JcePKCSPBEInputDecryptorProviderBuilder builder =
                        new JcePKCSPBEInputDecryptorProviderBuilder().setProvider("BC");
                InputDecryptorProvider idp = builder.build(keyPassphrase.toCharArray());
                pki = epki.decryptPrivateKeyInfo(idp);
            } else if (o instanceof PEMEncryptedKeyPair epki) {
                PEMKeyPair pkp = epki.decryptKeyPair(new BcPEMDecryptorProvider(keyPassphrase.toCharArray()));
                pki = pkp.getPrivateKeyInfo();
            } else {
                throw new PKCSException("Invalid encrypted private key class: " + o.getClass().getName());
            }
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
            return new SignatureKey(converter.getPrivateKey(pki), keyId);
        } catch (IOException | PKCSException ex) {
            logger.error(ex.getMessage(), ex);
            throw new RuntimeException(ex);
        }
    }

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

    public static String sign(LinkedHashMap<String, String> signatureFields, SignatureKey key) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
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


    public static String generateNonce() {
        StringBuilder nonce = new StringBuilder();
        for (int i = 0; i < NONCE_LENGTH; i++) {
            int index = RANDOM.nextInt(NONCE_ALPHABET.length());
            nonce.append(NONCE_ALPHABET.charAt(index));
        }
        return nonce.toString();
    }

    public static String getSHA512Digest(String input) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-512");
        byte[] hashBytes = digest.digest(
                input.getBytes(StandardCharsets.UTF_8));
        return "sha-512=:" + Base64.getEncoder().encodeToString(hashBytes) + ":";
    }

    public static String createSignatureParametersString(LinkedHashMap<String, String> signatureFields, SignatureKey key) {
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
}
