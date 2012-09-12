/*
 * Copyright 2007 Jesse Peterson
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

package com.jpeterson.littles3.bo;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.http.HttpServletRequest;

import org.apache.commons.codec.binary.Base64;

import com.jpeterson.littles3.S3ObjectRequest;
import de.desy.dcache.s3.Signature;
import de.desy.dcache.temp.FSLogger;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.security.SignatureException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.commons.codec.binary.Hex;

/**
 * Performs Amazon S3 Authentication.
 * 
 * @author Jesse Peterson, changed by s0525775
 */
public class S3Authenticator implements Authenticator {
    	public static final String HEADER_HTTP_METHOD_OVERRIDE = "X-HTTP-Method-Override";
    
	private static final String HEADER_AUTHORIZATION = "Authorization";

	private static final String AUTHORIZATION_TYPE = "AWS";

	private UserDirectory userDirectory;

	/**
	 * Empty constructor.
	 */
	public S3Authenticator() {

	}

	/**
	 * Authenticate the request using the prescribed Amazon S3 authentication
	 * mechanisms.
	 * 
	 * @param req
	 *            The original HTTP request.
	 * @param s3Request
	 *            The S3 specific information for authenticating the request.
	 * @return The authenticated <code>CanonicalUser</code> making the request.
	 * @throws RequestTimeTooSkewedException
	 *             Thrown if the request timestamp is outside of the allotted
	 *             timeframe.
	 */
	public CanonicalUser authenticate(HttpServletRequest req,
			S3ObjectRequest s3Request) throws AuthenticatorException {
		// check to see if anonymous request
		String authorization = req.getHeader(HEADER_AUTHORIZATION);

                // s0525775 - not wanted - either authenticated or nothing
                //if (authorization == null) {
                //	return new CanonicalUser(CanonicalUser.ID_ANONYMOUS);
                //}

		// attempting to be authenticated request

                // changed by s0525775
                // http://docs.amazonwebservices.com/AmazonS3/2006-03-01/dev/RESTAuthentication.html
                String HTTPverb = getMethod(req);
                String contentMD5 = req.getHeader("Content-MD5");
                String contentType = req.getHeader("Content-Type");
                String date = req.getHeader("Date");
                String canonicalizedAmzHeaders = getAmzHeaders(req);
                String canonicalizedResource = getResHeaders(req);
                
                if (contentMD5 == null) {
                    contentMD5 = "";
                }
                
                if (contentType == null) {
                    contentType = "";
                }

                String stringToSign = HTTPverb + "\n" +
                        contentMD5 + "\n" +
                        contentType + "\n" +
                        date + "\n" +
                        canonicalizedAmzHeaders +
                        canonicalizedResource;
                
                // the following code was already inactive in any case, false is always false
                // the code should verify if the signature/certificate is still valid
                // at the moment this doesn't get verified
		//if (false) {
		//	// check timestamp of request
		//	Date timestamp = s3Request.getTimestamp();
		//	if (timestamp == null) {
		//		throw new RequestTimeTooSkewedException("No timestamp provided");
		//	}
                //
		//	GregorianCalendar calendar = new GregorianCalendar();
		//	Date now = calendar.getTime();
		//	calendar.add(Calendar.MINUTE, 15);
		//	Date maximumDate = calendar.getTime();
		//	calendar.add(Calendar.MINUTE, -30);
		//	Date minimumDate = calendar.getTime();
                //
		//	if (timestamp.before(minimumDate)) {
		//		throw new RequestTimeTooSkewedException("Timestamp ["
		//				+ timestamp + "] too old. System time: " + now);
		//	}
                //
		//	if (timestamp.after(maximumDate)) {
		//		throw new RequestTimeTooSkewedException("Timestamp ["
		//				+ timestamp + "] too new. System time: " + now);
		//	}
		//}
                
		// authenticate request
		String[] fields = authorization.split(" ");

		if (fields.length != 2) {
			throw new InvalidSecurityException(
					"Unsupported authorization format");
		}

		if (!fields[0].equals(AUTHORIZATION_TYPE)) {
			throw new InvalidSecurityException(
					"Unsupported authorization type: " + fields[0]);
		}

		String[] keys = fields[1].split(":");

		if (keys.length != 2) {
			throw new InvalidSecurityException(
					"Invalid AWSAccesskeyId:Signature");
		}

		String signature = keys[1];
		String calculatedSignature = "";
                String stringToSignUTF8 = "";
		String accessKeyId = keys[0];
                byte[] hashSignature;
		//String secretAccessKey = userDirectory
		//		.getAwsSecretAccessKey(accessKeyId);
                String secretAccessKey="aGJSBPY5Cbafhb5UPKlbNRluXlFj9JIVqFx103w2";

                // deactivated by s0525775
		//try {
		//	SecretKey key = new SecretKeySpec(secretAccessKey.getBytes(),
		//			"HmacSHA1");
		//	Mac m = Mac.getInstance("HmacSHA1");
		//	m.init(key);
		//	m.update(s3Request.getStringToSign().getBytes());
		//	byte[] mac = m.doFinal();
		//	calculatedSignature = new String(Base64.encodeBase64(mac));
		//} catch (NoSuchAlgorithmException e) {
		//	throw new InvalidSecurityException(e);
		//} catch (InvalidKeyException e) {
		//	throw new InvalidSecurityException(e);
		//}
                
                // Signature = Base64(HMAC-SHA1(secretAccessKey, UTF-8-Encoding-Of(stringToSign)));
                // Authorization = "AWS" + " " + AWSAccessKeyId + ":" + Signature;

                try {
                    stringToSignUTF8 = URLEncoder.encode(stringToSign, "UTF-8");
                    calculatedSignature = Signature.calculateRFC2104HMAC(stringToSign, secretAccessKey);
                } catch (UnsupportedEncodingException ex) {
                    Logger.getLogger(S3Authenticator.class.getName()).log(Level.SEVERE, null, ex);
                } catch (SignatureException ex) {
                    Logger.getLogger(S3Authenticator.class.getName()).log(Level.SEVERE, null, ex);
                }

		System.out.println("-----------------");
		System.out.println("stringToSign: " + stringToSign);
		System.out.println("signature: " + signature);
		System.out.println("calculatedSignature: " + calculatedSignature);
		System.out.println("-----------------");
                
                String file2 = "/tmp/testlog.txt";
		String text2 = "-----------------\r\n";
		text2 += "stringToSign: \r\n>>" + stringToSign + "<<\r\n";
		text2 += "ClientSignature: " + signature + "\r\n";
		text2 += "ServerSignature: " + calculatedSignature + "\r\n";
		text2 += "-----------------\r\n\r\n";
                FSLogger.writeLog(file2, text2);

                // changed by s0525775
		if (calculatedSignature.equals(signature)) {
			// authenticated! needs to get verified
			return userDirectory.getCanonicalUser(accessKeyId);
		} else {
			throw new SignatureDoesNotMatchException(
					"Provided signature doesn't match calculated value");
		}
	}
        
        /**
	 * Returns the HTTP method of the request. Implements logic to allow an
	 * "override" method, specified by the header
	 * <code>HEADER_HTTP_METHOD_OVERRIDE</code>. If the override method is
	 * provided, it takes precedence over the actual method derived from
	 * <code>request.getMethod()</code>.
	 * 
	 * @param request
	 *            The request being processed.
	 * @return The method of the request.
	 * @see #HEADER_HTTP_METHOD_OVERRIDE
	 */
	public static String getMethod(HttpServletRequest request) {
                String HTTPverb = ""; 
		String method = request.getHeader(HEADER_HTTP_METHOD_OVERRIDE);

		if (method == null) {
			method = request.getMethod();
		}

                if (method.equalsIgnoreCase("GET")) {
                    // read
                    HTTPverb = "GET"; 
                } else if (method.equalsIgnoreCase("PUT")) {
                    // create
                    HTTPverb = "PUT";
                } else if (method.equalsIgnoreCase("DELETE")) {
                    // remove
                    HTTPverb = "DELETE";
                }

                return HTTPverb;
	}
        
        /**
	 * Returns the HTTP method of the request. Implements logic to allow an
	 * "override" method, specified by the header
	 * <code>HEADER_HTTP_METHOD_OVERRIDE</code>. If the override method is
	 * provided, it takes precedence over the actual method derived from
	 * <code>request.getMethod()</code>.
	 * 
	 * @param request
	 *            The request being processed.
	 * @return The method of the request.
	 * @see #HEADER_HTTP_METHOD_OVERRIDE
	 */
	public static String getAmzHeaders(HttpServletRequest request) {
            String amzHeaders = "";
            /*
                
                List<String> amzHeadersList = new ArrayList<String>();
                amzHeadersList.clear();
                
                for (Enumeration e1 = request.getHeaderNames(); e1.hasMoreElements();) {
                    String amzHeader = e1.nextElement().toString().toLowerCase();
                            
                    if (amzHeader.equalsIgnoreCase("x-amz-")) {
                        String itemList = amzHeader.split(":")[0] + ":";

                        for (Enumeration e2 = request.getHeaders(amzHeader); e2.hasMoreElements();) {
                            String element = e1.nextElement().toString().toLowerCase().replace(" ", "").trim();
                            String amzHeaderName = element.split(":")[0];
                            itemList += element.replace(amzHeaderName, "").replace(":", "") + ",";
                        }
                        
                        amzHeadersList.add(itemList.substring(0, itemList.length()-1));
                    }
                }
                
                sortStringList(amzHeadersList);
                
                for (String element : amzHeadersList) {
                    amzHeaders += element + "\n";
                }
                
                if (!amzHeaders.isEmpty()) {
                    amzHeaders = amzHeaders.substring(0, amzHeaders.length()-1);
                }
                
                */
                amzHeaders = "";
		return amzHeaders;
	}

        /**
	 * Returns the HTTP method of the request. Implements logic to allow an
	 * "override" method, specified by the header
	 * <code>HEADER_HTTP_METHOD_OVERRIDE</code>. If the override method is
	 * provided, it takes precedence over the actual method derived from
	 * <code>request.getMethod()</code>.
	 * 
	 * @param request
	 *            The request being processed.
	 * @return The method of the request.
	 * @see #HEADER_HTTP_METHOD_OVERRIDE
	 */
	public static String getResHeaders(HttpServletRequest request) {
                String resHeader = "";
                String bucketAndOrHost = "";
                String resource = "";
		String method = request.getHeader(HEADER_HTTP_METHOD_OVERRIDE);
                String hostHeader = request.getHeader("Host");
                
                if (hostHeader != null) {
                    if (hostHeader.contains(".")) { //in this order
                        bucketAndOrHost = "/" + hostHeader.split(".")[0];
                    } else if (hostHeader.contains(":")) {
                        bucketAndOrHost = "/" + hostHeader.split(":")[0];
                    } else if (hostHeader.contains("/")) {
                        bucketAndOrHost = "/" + hostHeader.split("/")[0];
                    }
                } else {
                    bucketAndOrHost = "/";
                }

                if (method != null) {
                    if (method.contains(" ")) {
                        resource += method.split(" ")[1];
                    }
		} else {
                    resource += request.getRequestURI();
                }
                
                if (request.getAttribute("versioning") != null) {
                    resource += request.getAttribute("versioning");
                }
                                
                if (resource.startsWith("/")) {
                    resource = resource.substring(1, resource.length());
                }
                resHeader = bucketAndOrHost + "/" + resource;
                
		return resHeader;
	}        
        
        /**
	 * Get the <code>UserDirectory</code> for accessing user information for
	 * authentication.
	 * 
	 * @return The <code>UserDirectory</code> for accessing user information for
	 *         authentication.
	 */
	public UserDirectory getUserDirectory() {
		return userDirectory;
	}

	/**
	 * Set the <code>UserDirectory</code> for accessing user information for
	 * authentication.
	 * 
	 * @param userDirectory
	 *            The <code>UserDirectory</code> for accessing user information
	 *            for authentication.
	 */
	public void setUserDirectory(UserDirectory userDirectory) {
		this.userDirectory = userDirectory;
	}
        
	/**
	 * Set the <code>UserDirectory</code> for accessing user information for
	 * authentication.
	 * 
	 * @param userDirectory
	 *            The <code>UserDirectory</code> for accessing user information
	 *            for authentication.
	 */
        private static void sortStringList(List<String> strings){
            Collections.sort(strings, String.CASE_INSENSITIVE_ORDER);
        }
        
}
