/*
 * Copyright 2012 Amazon / s0525775.
 * http://docs.amazonwebservices.com/AmazonSimpleDB/latest/DeveloperGuide/HMACAuth.html
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

import org.apache.commons.codec.binary.Base64;

/**
 *
 * @author s0525775
 * 
 */
public class S3Encoding {
    /**
    * Performs base64-encoding of input bytes.
    *
    * @param rawData * Array of bytes to be encoded.
    * @return * The base64 encoded string representation of rawData.
    */
    public static String EncodeBase64(byte[] rawData) {
        return new String(Base64.encodeBase64(rawData));
    }    
}
