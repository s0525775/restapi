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

import de.desy.dcache.s3.db.DatabaseConnection;
import java.security.SignatureException;
import java.util.ArrayList;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.http.HttpServletRequest;

/**
 *
 * @author s0525775
 */
public class S3Authentication {

    private ArrayList al;
    
    public S3Authentication () {
    }
    
    private void _convertRequestToArrayList(HttpServletRequest req) {
        al = new ArrayList();
        al.clear();
        al.add(req.getRequestURI());
        al.add(req.getHeader("Host"));
        al.add(req.getHeader("Authorization"));
        al.add(req.getHeader("Date"));
    }
    
    private void _buildStringToSign() {
    }

    private void _buildSignedRequest() {
    }

    public String calcServerS3Signature(String data) {
        String result = "";
        DatabaseConnection dbconn = new DatabaseConnection();
        dbconn.connect();
        ArrayList fetchDB = dbconn.fetchDataByAccessKeyId("AKIAJ2FBI53FU5ECPSUR");
        String SecretAccessKey = fetchDB.get(7).toString();
        
        dbconn.disconnect();        
        return result;
    }

    public String getClientS3Signature(String data) {
        return "AKIAJ2FBI53FU5ECPSUR";
    }
    
    public boolean authenticate(String data) {
        return getClientS3Signature(data).equals(calcServerS3Signature(data));
    }
    
    /**
    * This class defines common routines for generating
    * authentication signatures for AWS Platform requests.
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
    public String calculateRFC2104HMAC(String data, String key)
    throws java.security.SignatureException
    {
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
            result = S3Encoding.EncodeBase64(rawHmac);
        } catch (Exception e) {
            throw new SignatureException("Failed to generate HMAC: " + e.getMessage());
        }
            return result;
        }
    }
    
}
