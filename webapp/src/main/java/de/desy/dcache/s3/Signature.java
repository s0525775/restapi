/*
 * Copyright 2012 s0525775 / DESY / Amazon.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.desy.dcache.s3;

import java.security.SignatureException;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.codec.binary.Base64;

/**
*
* @author Amazon
* http://docs.amazonwebservices.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/AuthJavaSampleHMACSignature.html
*/
/**
* This class defines common routines for generating
* authentication signatures for AWS requests.
*/
public class Signature {
        private static final String HMAC_SHA1_ALGORITHM = "HmacSHA1";

        /**
        * Computes RFC 2104-compliant HMAC signature.
        * * @param data
        * The data to be signed.
        * @param key
        * The signing key.
        * @return
        * The Base64-encoded RFC 2104-compliant HMAC signature.
        * @throws
        * java.security.SignatureException when signature generation fails
        */
        public static String calculateRFC2104HMAC(String data, String key)
                throws java.security.SignatureException {
                String result;
                try {
                        // get an hmac_sha1 key from the raw key bytes
                        SecretKeySpec signingKey = new SecretKeySpec(key.getBytes(), HMAC_SHA1_ALGORITHM);

                        // get an hmac_sha1 Mac instance and initialize with the signing key
                        Mac mac = Mac.getInstance(HMAC_SHA1_ALGORITHM);
                        mac.init(signingKey);

                        // compute the hmac on input data bytes
                        byte[] rawHmac = mac.doFinal(data.getBytes());

                        // base64-encode the hmac
                        result = new String(Base64.encodeBase64(rawHmac));

                } catch (Exception e) {
                        throw new SignatureException("Failed to generate HMAC: " + e.getMessage());
                }
                return result;
        }
}