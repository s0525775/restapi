package com.jpeterson.littles3.bo;

import javax.servlet.http.HttpServletRequest;

import com.jpeterson.littles3.S3ObjectRequest;

/**
 * Simple Authenticator used for development.
 * Not in function anymore. s0525775.
 * 
 * @author Jesse Peterson
 */
public class HackAuthenticator implements Authenticator {
	private Authenticator authenticator;

	public HackAuthenticator() {

	}

	public Authenticator getAuthenticator() {
		return authenticator;
	}

	public void setAuthenticator(Authenticator authenticator) {
		this.authenticator = authenticator;
	}

	/**
	 * This implementation looks for an HTTP request header named "x-hack-user".
	 * If found, the request is authenticated and the value of the header is
	 * used to create a <code>CanonicalUser</code>. If not found and another
	 * <code>authenticator</code> has been provided, the request will be forward
	 * to the <code>authenticator</code>. If no <code>authenticator</code>
	 * provided, the request is considered anonymous.
	 */
	public CanonicalUser authenticate(HttpServletRequest req,
			S3ObjectRequest s3Request) throws AuthenticatorException {
//		String username = req.getHeader("x-hack-user");
//		if (username != null) {
//			System.out.println("HACK! USING USERNAME FROM HEADER: " + username);
//			return new CanonicalUser(username);
//		} else if (authenticator != null) {
//			return authenticator.authenticate(req, s3Request);
//		}
//		return new CanonicalUser(CanonicalUser.ID_ANONYMOUS);            
                String authorization = req.getHeader("Authorization").toString();
                String[] fields = authorization.split(" ");
                if (fields.length != 2) {
                        throw new InvalidSecurityException("Unsupported authorization format");
                }
                if (!fields[0].equals("AWS")) {
                        throw new InvalidSecurityException("Unsupported authorization type: " + fields[0]);
                }
                String[] keys = fields[1].split(":");
                if (keys.length < 2) {
                        throw new InvalidSecurityException("No, but no AWS Key? Nothing similar?");
                }
                String accessKeyId = keys[0];
                return new CanonicalUser(accessKeyId);
	}
}
