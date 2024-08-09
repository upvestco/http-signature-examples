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

import java.io.FileInputStream;
import java.io.IOException;
import java.util.Properties;

/* A little helper class to reads the properties from the env.properties file */
public class ConfigReader {

    private static final String PROPERTIES_FILE = "env.properties";
    private static final String[] REQUIRED_PROPERTIES = {
            "UPVEST_API_HTTP_SIGN_PRIVATE_KEY_FILE",
            "UPVEST_API_HTTP_SIGN_PRIVATE_KEY_PASSPHRASE",
            "UPVEST_API_KEY_ID",
            "UPVEST_URL",
            "UPVEST_API_CLIENT_ID",
            "UPVEST_API_CLIENT_SECRET",
            "UPVEST_API_CLIENT_SCOPE",
    };

    public static Properties readProperties() throws IOException {
        Properties properties = new Properties();
        try (FileInputStream inputStream = new FileInputStream(PROPERTIES_FILE)) {
            properties.load(inputStream);
        }

        for (String key : REQUIRED_PROPERTIES) {
            if (properties.getProperty(key) == null) {
                throw new IOException("Missing required property: " + key);
            }
        }
        return properties;
    }
}