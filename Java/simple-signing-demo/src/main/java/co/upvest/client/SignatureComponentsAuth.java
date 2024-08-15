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


import java.net.URI;
import java.util.Objects;

/**
 * Container for the mandatory components of the signature for the Auth endpoint.
 * @param url
 * @param accept
 * @param apiVersion
 * @param bodyContent
 * @param contentType
 */
public record SignatureComponentsAuth(URI url, String accept, String apiVersion, String bodyContent,
                                      String contentType) {

    public SignatureComponentsAuth {
        Objects.requireNonNull(url, "url cannot be null");
        Objects.requireNonNull(accept, "accept cannot be null");
        Objects.requireNonNull(apiVersion, "apiVersion cannot be null");
        Objects.requireNonNull(bodyContent, "bodyContent cannot be null");
        Objects.requireNonNull(contentType, "contentType cannot be null");

        if (accept.isEmpty() || apiVersion.isEmpty() || bodyContent.isEmpty() || contentType.isEmpty()) {
            throw new IllegalArgumentException("String arguments cannot be empty");
        }
    }

    public String httpMethod() {
        return "POST";
    }
}


