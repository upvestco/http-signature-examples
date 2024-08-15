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
import java.security.Security;

/**
 * Utility class for loading private keys from files.
 */
public class KeyUtility {

    private static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(KeyUtility.class);

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private KeyUtility() {
        // no instances, just static methods
    }

    /**
     * Load a private key from a file.
     *
     * @param keyFileName   the file name of the private key
     * @param keyPassphrase the passphrase for the private key
     * @param keyId         the key ID
     * @return the private key
     */
    public static SigningKey getSignatureKey(String keyFileName, String keyPassphrase, String keyId) {
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
            return new SigningKey(converter.getPrivateKey(pki), keyId);
        } catch (IOException | PKCSException ex) {
            logger.error(ex.getMessage(), ex);
            throw new RuntimeException(ex);
        }
    }
}
