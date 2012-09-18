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
import java.net.InetAddress;
import java.net.URLEncoder;
import java.net.UnknownHostException;
import java.security.SignatureException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.configuration.Configuration;
import org.apache.commons.configuration.ConfigurationException;
import org.apache.commons.configuration.PropertiesConfiguration;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

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
        
        private Log logger;
        
        private Configuration configuration;
        
	/**
	 * Default configuration file name.
	 */
	public static final String DEFAULT_CONFIGURATION = "StorageEngine.properties";

        /**
	 * Configuration property defining the HTTP Host that this engine is
	 * serving.
	 */
	public static final String CONFIG_HOST = "host";

	/**
	 * This token can be used in a <code>CONFIG_HOST</code> for the local host.
	 * It is resolved via
	 * <code>InetAddress.getLocalHost().getCanonicalHostName()</code>.
	 */
	public static final String CONFIG_HOST_TOKEN_RESOLVED_LOCAL_HOST = "$resolvedLocalHost$";

	/**
	 * Empty constructor.
	 */
	public S3Authenticator() {
                logger = LogFactory.getLog(this.getClass());
		try {
			configuration = new PropertiesConfiguration(DEFAULT_CONFIGURATION);
		} catch (ConfigurationException e) {
			logger
					.warn("Unable to load default properties-based configuration: "
							+ DEFAULT_CONFIGURATION);
			configuration = new PropertiesConfiguration();
		}
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
                
                userDirectory = new StaticUserDirectory();
                
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
                                
                // the following code was already inactive in any case, false is always false.
                // the code should verify if the requests is still valid.
                // in the future, requests should be limited in time and only
                // be valid for 12 or 24 hours(?). just as a suggestion.
                // at the moment this part doesn't get verified, requests are always valid.
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
		String accessKeyId = keys[0];
		String secretAccessKey = userDirectory.getAwsSecretAccessKey(accessKeyId);

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
                
                // changed by s0525775, the following two comment lines aren't real code.
                // Signature = Base64(HMAC-SHA1(secretAccessKey, UTF-8-Encoding-Of(stringToSign)));
                // Authorization = "AWS" + " " + AWSAccessKeyId + ":" + Signature;

                try {
                    calculatedSignature = Signature.calculateRFC2104HMAC(stringToSign, secretAccessKey);
                } catch (SignatureException ex) {
                    Logger.getLogger(S3Authenticator.class.getName()).log(Level.SEVERE, null, ex);
                }

                // Output in IDE
		System.out.println("-----------------");
		System.out.println("stringToSign: " + stringToSign);
		System.out.println("signature: " + signature);
		System.out.println("calculatedSignature: " + calculatedSignature);
		System.out.println("-----------------");
                
                // Output for later if you haven't an IDE, just for tests
                String file1 = "/tmp/testlog.txt";
		String text1 = "-----------------\r\n";
		text1 += "stringToSign: \r\n>>" + stringToSign + "<<\r\n";
		text1 += "ClientSignature: " + signature + "\r\n";
		text1 += "ServerSignature: " + calculatedSignature + "\r\n";
		text1 += "-----------------\r\n\r\n";
                FSLogger.writeLog(file1, text1);

                // changed by s0525775
		if (calculatedSignature.equals(signature)) {
                    // authenticated!
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
	public String getAmzHeaders(HttpServletRequest request) {  //still untested
                String amzHeaders = "";

                List<String> amzHeadersList = new ArrayList<String>();
                amzHeadersList.clear();
                
                for (Enumeration e1 = request.getHeaderNames(); e1.hasMoreElements();) {
                    // regarding to the Amazon rules, the Amazon headers shall be lower case 
                    String amzHeader = e1.nextElement().toString().toLowerCase();
                        
                    // searches for all Amazon headers and their values
                    if (amzHeader.equalsIgnoreCase("x-amz-")) {
                        String itemList = "";
                        itemList += amzHeader;
                        itemList += ":";

                        // regarding to the Amazon rules, the values of equal Amazon headers  
                        // shall get put together, seperated by commas
                        for (Enumeration e2 = request.getHeaders(amzHeader); e2.hasMoreElements();) {
                            String element = e1.nextElement().toString().toLowerCase().trim();
                            String amzHeaderName = "";
                            itemList += element.replace(amzHeaderName, "");
                            itemList += ",";
                        }
                        // removes the last comma and adds everything to a list
                        amzHeadersList.add(itemList.substring(0, itemList.length()-1));
                    }
                }
                
                // regarding to the Amazon rules, the Amazon headers shall be 
                // lexicographically sorted 
                sortStringList(amzHeadersList);
                
                // converts the sorted list into a string after it got sorted
                for (String element : amzHeadersList) {
                    amzHeaders += element + "\n";
                }
                
                // removes the last return
                if (!amzHeaders.isEmpty()) {
                    amzHeaders = amzHeaders.substring(0, amzHeaders.length()-1);
                }
                
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
	public String getResHeaders(HttpServletRequest request) {
                String resHeader = "";
                String bucket = "";
                String resource = "";
		String method = request.getHeader(HEADER_HTTP_METHOD_OVERRIDE);
                String hostHeader = request.getHeader("Host").toLowerCase();
                String host = resolvedHost().toLowerCase();
                
                // decides if path related or virtual host related 
                // and gets the bucket name if virtual host related
                hostHeader = hostHeader.replace(host, "");
                if (hostHeader != null) {
                    if (hostHeader.indexOf('/') > 0) {  // in this order
                        // path related
                        bucket = "";
                    } else if (hostHeader.indexOf('.') > 0) {
                        // virtual host related
                        bucket += "/" + hostHeader.substring(0, hostHeader.indexOf('.'));
                    }
                }
                
                // Output for later if you haven't an IDE, just for tests
                String file1 = "/tmp/testlog.txt";
		String text1 = "-----------------\r\n";
		text1 += "host: \r\n>>" + host + "<<\r\n";
		text1 += "hostHeader: " + hostHeader + "\r\n";
		text1 += "-----------------\r\n\r\n";
                FSLogger.writeLog(file1, text1);

                // tries to get the ressource
                // and gets the bucket name if path related
                if (method != null) {
                    if (method.indexOf(' ') > 0) {
                        resource += method.substring(0, method.indexOf(' '));
                    }
		} else {
                    resource += request.getRequestURI();
                }
                
                // adds the Query String to the resource
                // attention, it has to follow the 4th Amazon rule, which says:
                // If the request addresses a sub-resource, like ?versioning, ?location, ?acl, ?torrent, ?lifecycle, 
                // or ?versionid append the sub-resource, its value if it has one, and the question mark. Note that 
                // in case of multiple sub-resources, sub-resources must be lexicographically sorted by sub-resource 
                // name and separated by '&'. e.g. ?acl&versionId=value.
                // The list of sub-resources that must be included when constructing the CanonicalizedResource 
                // Element are: acl, lifecycle, location, logging, notification, partNumber, policy, requestPayment, 
                // torrent, uploadId, uploads, versionId, versioning, versions and website.
                // If the request specifies query string parameters overriding the response header values (see Get 
                // Object), append the query string parameters, and its values. When signing you do not encode these
                // values. However, when making the request, you must encode these parameter values. The query string 
                // parameters in a GET request include response-content-type, response-content-language, 
                // response-expires, response-cache-control, response-content-disposition, response-content-encoding.
                // The delete query string parameter must be including when creating the CanonicalizedResource for a 
                // Multi-Object Delete request.
                if (request.getQueryString() != null) {
                    resource += "?" + getQueryString(request.getQueryString());
                }
                
                // formats the ressource String so that it can't be "//" or only "?".
                if (resource.startsWith("/")) {
                    resource = resource.substring(1, resource.length());
                    if (resource.contentEquals("?")) {
                        resource = "";
                    }
                }
                resHeader = bucket + "/" + resource;
                
		return resHeader;
	}        
        
        /**
         * Returns the HTTP method of the request. Implements logic to allow an
	 * "override" method, specified by the header
	 * <code>HEADER_HTTP_METHOD_OVERRIDE</code>. If the override method is
	 * provided, it takes precedence over the actual method derived from
	 * <code>request.getMethod()</code>. 
         * 
         * @param tmpQueryString
         * @return 
         */
        public String getQueryString(String tmpQueryString) {  //still untested
                String queryString = "";
                String tQueryString = "";
                List<String> tmpList = new ArrayList<String>();
                tmpList.clear();

                // for the later signature the following keys in sArray must be case sensitive
                // otherwise the signature will be wrong; only those keys will be accepted
                String sArray[] = new String[]{"acl","lifecycle","location","logging","notification",
                    "partNumber","policy","requestPayment","torrent","uploadId","uploads","versionId",
                    "versioning","versions","website"};

                // removes "?" from the Query string, it will be added later again
                tmpQueryString = tmpQueryString.replace("?", "");

                // splits the Query string so that it can get lexicographically sorted later
                String tmpArray[] = tmpQueryString.split("&");

                if (tmpArray.length > 0) {
                    // accepts a known key, even if it is case insensitive; ignores unknown keys
                    for (int i = 0; i < tmpArray.length; i++) {
                        for (int j = 0; j < sArray.length; j++) {
                            if (tmpArray[i].toLowerCase().contains(sArray[j].toLowerCase())) {
                                // splits the value from the key
                                String keyVal[] = tmpArray[i].split("=");
                                if (keyVal.length > 1) {
                                    // replaces the old key (case sensitive or not) 
                                    // by the case sensitive key
                                    String tmpListVal = sArray[i] + "=" + keyVal[1]; 
                                    // adds the new key and value to a list
                                    tmpList.add(tmpListVal);
                                }
                            }
                        }
                    }
                }
            
                // sorts the list lexicographically
                if (!tmpList.isEmpty()) {
                    sortStringList(tmpList);
                }
                // converts the lexicographically sorted list into a 
                // lexicographically sorted string
                for (String element : tmpList) {
                    tQueryString += element + "&";
                }
                // removes the last "&" from the string
                if (!tQueryString.isEmpty()) {
                    tQueryString = tQueryString.substring(0, tQueryString.length()-1);
                }
                // adds a "?" in front of the new validated Query string
                if (!tQueryString.isEmpty()) {
                    queryString = "?" + tQueryString;
                }
            
                return queryString;
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
	 * Sorts a String list lexicographically and case insensitive.
	 * 
	 * @param strings
	 *            The <code>UserDirectory</code> for accessing user information
	 *            for authentication.
	 */
        private void sortStringList(List<String> strings){
                Collections.sort(strings, String.CASE_INSENSITIVE_ORDER);
        }
        
	/**
	 * Resolves the configured host name, replacing any tokens in the configured
	 * host name value.
	 * 
	 * @return The configured host name after any tokens have been replaced.
	 * @see #CONFIG_HOST
	 * @see #CONFIG_HOST_TOKEN_RESOLVED_LOCAL_HOST
	 */
	public String resolvedHost() {
		String configHost;

		configHost = configuration.getString(CONFIG_HOST);
		logger.debug("configHost: " + configHost);

		if (configHost.indexOf(CONFIG_HOST_TOKEN_RESOLVED_LOCAL_HOST) >= 0) {
			InetAddress localHost;
			String resolvedLocalHost = "localhost";

			try {
				localHost = InetAddress.getLocalHost();
				resolvedLocalHost = localHost.getCanonicalHostName();
			} catch (UnknownHostException e) {
				logger.fatal("Unable to resolve local host", e);
			}

			configHost = configHost.replace(
					CONFIG_HOST_TOKEN_RESOLVED_LOCAL_HOST, resolvedLocalHost);
		}

                // changed by s0525775
                if (configHost.indexOf(':') > 0) {
                    configHost = configHost.substring(0, configHost.indexOf(':'));
                }
                
		return configHost;
	}
}
