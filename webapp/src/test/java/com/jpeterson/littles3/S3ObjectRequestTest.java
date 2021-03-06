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

package com.jpeterson.littles3;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.text.SimpleDateFormat;
import java.util.GregorianCalendar;
import java.util.TimeZone;

import javax.servlet.http.HttpServletRequest;

import junit.framework.Test;
import junit.framework.TestSuite;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jmock.Mock;
import org.jmock.MockObjectTestCase;

import com.jpeterson.littles3.bo.AuthenticatorException;
import com.jpeterson.littles3.bo.CanonicalUser;
import com.jpeterson.littles3.bo.HackAuthenticator;
import com.jpeterson.littles3.bo.S3Authenticator;

public class S3ObjectRequestTest extends MockObjectTestCase {
	private Log logger;

	/**
	 * Create the test case
	 * 
	 * @param testName
	 *            name of the test case
	 */
	public S3ObjectRequestTest(String testName) {
		super(testName);

		logger = LogFactory.getLog(this.getClass());
		logger.debug("S3ObjectTest");
	}

	/**
	 * @return the suite of tests being tested
	 */
	public static Test suite() {
		return new TestSuite(S3ObjectRequestTest.class);
	}

	/**
	 * Test getting/setting the serviceEndpoint.
	 */
	public void test_serviceEndpoint() {
		S3ObjectRequest o = new S3ObjectRequest();

		assertEquals("Unexpected serviceEndpoint", null, o.getServiceEndpoint());
		o.setServiceEndpoint("http://localhost");
		assertEquals("Unexpected serviceEndpoint", "http://localhost", o
				.getServiceEndpoint());
	}

	/**
	 * Test getting/setting the bucket.
	 */
	public void test_bucket() {
		S3ObjectRequest o = new S3ObjectRequest();

		assertEquals("Unexpected bucket", null, o.getBucket());
		o.setBucket("testBucket");
		assertEquals("Unexpected bucket", "testBucket", o.getBucket());
	}

	/**
	 * Test getting/setting the key.
	 */
	public void test_key() {
		S3ObjectRequest o = new S3ObjectRequest();

		assertEquals("Unexpected key", null, o.getKey());
		o.setKey("testKey");
		assertEquals("Unexpected key", "testKey", o.getKey());
	}

	/**
	 * Test a basic <code>create</code>.
	 */
	public void xtest_create() {
		S3ObjectRequest o;
		Mock mockHttpServletRequest = mock(HttpServletRequest.class);

		mockHttpServletRequest.expects(once()).method("getPathInfo").will(
				returnValue("/myBucket/myKey.txt"));
		mockHttpServletRequest.expects(once()).method("getHeader").with(
				eq("Host")).will(returnValue("localhost"));
		mockHttpServletRequest.expects(once()).method("getRequestURL").will(
				returnValue(new StringBuffer(
						"http://localhost/context/myBucket/myKey.txt")));
		mockHttpServletRequest.expects(once()).method("getUserPrincipal").will(
				returnValue(new CanonicalUser("unitTest")));
		mockHttpServletRequest.expects(once()).method("getHeader").with(
				eq("x-hack-user")).will(returnValue(null));

		try {
			HackAuthenticator authenticator = new HackAuthenticator();
			authenticator.setAuthenticator(new S3Authenticator());

			o = S3ObjectRequest.create(
					(HttpServletRequest) mockHttpServletRequest.proxy(),
					"localhost", authenticator);
		} catch (IllegalArgumentException e) {
			e.printStackTrace();
			fail("Unexpected exception");
			return;
		} catch (AuthenticatorException e) {
			e.printStackTrace();
			fail("Unexpected exception");
			return;
		}

		assertEquals("Unexpected serviceEndpoint", "http://localhost/context",
				o.getServiceEndpoint());
		assertEquals("Unexpected bucket", "myBucket", o.getBucket());
		assertEquals("Unexpected key", "myKey.txt", o.getKey());
		assertEquals("Unexpected requestor", new CanonicalUser("unitTest"), o
				.getRequestor());
	}

	/**
	 * Test a basic <code>create</code> with an anonymous request.
	 */
	public void xtest_createAnonymousRequest() {
		S3ObjectRequest o;
		Mock mockHttpServletRequest = mock(HttpServletRequest.class);

		mockHttpServletRequest.expects(once()).method("getPathInfo").will(
				returnValue("/myBucket/myKey.txt"));
		mockHttpServletRequest.expects(once()).method("getHeader").with(
				eq("Host")).will(returnValue("localhost"));
		mockHttpServletRequest.expects(once()).method("getRequestURL").will(
				returnValue(new StringBuffer(
						"http://localhost/context/myBucket/myKey.txt")));
		mockHttpServletRequest.expects(once()).method("getUserPrincipal").will(
				returnValue(null));
		mockHttpServletRequest.expects(once()).method("getHeader").with(
				eq("x-hack-user")).will(returnValue(null));

		try {
			HackAuthenticator authenticator = new HackAuthenticator();
			authenticator.setAuthenticator(new S3Authenticator());

			o = S3ObjectRequest.create(
					(HttpServletRequest) mockHttpServletRequest.proxy(),
					"localhost", authenticator);
		} catch (IllegalArgumentException e) {
			e.printStackTrace();
			fail("Unexpected exception");
			return;
		} catch (AuthenticatorException e) {
			e.printStackTrace();
			fail("Unexpected exception");
			return;
		}

		assertEquals("Unexpected serviceEndpoint", "http://localhost/context",
				o.getServiceEndpoint());
		assertEquals("Unexpected bucket", "myBucket", o.getBucket());
		assertEquals("Unexpected key", "myKey.txt", o.getKey());
		assertEquals("Unexpected requestor", new CanonicalUser(
				CanonicalUser.ID_ANONYMOUS), o.getRequestor());
	}

	/**
	 * Test a basic <code>create</code> but with a space in the key.
	 */
	public void xtest_createWithSpace() {
		S3ObjectRequest o;
		Mock mockHttpServletRequest = mock(HttpServletRequest.class);

		mockHttpServletRequest.expects(once()).method("getPathInfo").will(
				returnValue("/myBucket/my Key.txt"));
		mockHttpServletRequest.expects(once()).method("getHeader").with(
				eq("Host")).will(returnValue("localhost"));
		mockHttpServletRequest.expects(once()).method("getRequestURL").will(
				returnValue(new StringBuffer(
						"http://localhost/context/myBucket/my%20Key.txt")));
		mockHttpServletRequest.expects(once()).method("getUserPrincipal").will(
				returnValue(new CanonicalUser("unitTest")));
		mockHttpServletRequest.expects(once()).method("getHeader").with(
				eq("x-hack-user")).will(returnValue(null));

		try {
			HackAuthenticator authenticator = new HackAuthenticator();
			authenticator.setAuthenticator(new S3Authenticator());

			o = S3ObjectRequest.create(
					(HttpServletRequest) mockHttpServletRequest.proxy(),
					"localhost", authenticator);
		} catch (IllegalArgumentException e) {
			e.printStackTrace();
			fail("Unexpected exception");
			return;
		} catch (AuthenticatorException e) {
			e.printStackTrace();
			fail("Unexpected exception");
			return;
		}

		assertEquals("Unexpected serviceEndpoint", "http://localhost/context",
				o.getServiceEndpoint());
		assertEquals("Unexpected bucket", "myBucket", o.getBucket());
		assertEquals("Unexpected key", "my Key.txt", o.getKey());
	}

	/**
	 * Test a <code>create</code> with no key but with a slash character after
	 * the bucket.
	 */
	public void xtest_createNoKeyBucketEndsWithSlash() {
		S3ObjectRequest o;
		Mock mockHttpServletRequest = mock(HttpServletRequest.class);

		mockHttpServletRequest.expects(once()).method("getPathInfo").will(
				returnValue("/myBucket/"));
		mockHttpServletRequest.expects(once()).method("getHeader").with(
				eq("Host")).will(returnValue("localhost"));
		mockHttpServletRequest.expects(once()).method("getRequestURL").will(
				returnValue(new StringBuffer(
						"http://localhost/context/myBucket/")));
		mockHttpServletRequest.expects(once()).method("getUserPrincipal").will(
				returnValue(new CanonicalUser("unitTest")));
		mockHttpServletRequest.expects(once()).method("getHeader").with(
				eq("x-hack-user")).will(returnValue(null));

		try {
			HackAuthenticator authenticator = new HackAuthenticator();
			authenticator.setAuthenticator(new S3Authenticator());

			o = S3ObjectRequest.create(
					(HttpServletRequest) mockHttpServletRequest.proxy(),
					"localhost", authenticator);
		} catch (IllegalArgumentException e) {
			e.printStackTrace();
			fail("Unexpected exception");
			return;
		} catch (AuthenticatorException e) {
			e.printStackTrace();
			fail("Unexpected exception");
			return;
		}

		assertEquals("Unexpected serviceEndpoint", "http://localhost/context",
				o.getServiceEndpoint());
		assertEquals("Unexpected bucket", "myBucket", o.getBucket());
		assertNull("Unexpected key", o.getKey());
	}

	/**
	 * Test a <code>create</code> using virtual hosting of buckets. Ordinary
	 * method.
	 */
	public void xtest_virtualHostingOrdinaryMethod() {
		S3ObjectRequest o;
		Mock mockHttpServletRequest = mock(HttpServletRequest.class);

		mockHttpServletRequest.expects(once()).method("getPathInfo").will(
				returnValue("/johnsmith/homepage.html"));
		mockHttpServletRequest.expects(once()).method("getRequestURL").will(
				returnValue(new StringBuffer(
						"http://s3.amazonaws.com/johnsmith/homepage.html")));
		mockHttpServletRequest.expects(once()).method("getHeader").with(
				eq("Host")).will(returnValue("s3.amazonaws.com"));
		mockHttpServletRequest.expects(once()).method("getUserPrincipal").will(
				returnValue(new CanonicalUser("unitTest")));
		mockHttpServletRequest.expects(once()).method("getHeader").with(
				eq("x-hack-user")).will(returnValue(null));

		try {
			HackAuthenticator authenticator = new HackAuthenticator();
			authenticator.setAuthenticator(new S3Authenticator());

			o = S3ObjectRequest.create(
					(HttpServletRequest) mockHttpServletRequest.proxy(),
					"s3.amazonaws.com", authenticator);
		} catch (IllegalArgumentException e) {
			e.printStackTrace();
			fail("Unexpected exception");
			return;
		} catch (AuthenticatorException e) {
			e.printStackTrace();
			fail("Unexpected exception");
			return;
		}

		assertEquals("Unexpected serviceEndpoint", "http://s3.amazonaws.com", o
				.getServiceEndpoint());
		assertEquals("Unexpected bucket", "johnsmith", o.getBucket());
		assertEquals("Unexpected key", "homepage.html", o.getKey());
	}

	/**
	 * Test a <code>create</code> using virtual hosting of buckets. HTTP 1.0,
	 * contains no Host header.
	 */
	public void xtest_virtualHostingHTTP10() {
		S3ObjectRequest o;
		Mock mockHttpServletRequest = mock(HttpServletRequest.class);

		mockHttpServletRequest.expects(once()).method("getPathInfo").will(
				returnValue("/johnsmith/homepage.html"));
		mockHttpServletRequest.expects(once()).method("getRequestURL").will(
				returnValue(new StringBuffer(
						"http://s3.amazonaws.com/johnsmith/homepage.html")));
		mockHttpServletRequest.expects(once()).method("getHeader").with(
				eq("Host")).will(returnValue(null));
		mockHttpServletRequest.expects(once()).method("getUserPrincipal").will(
				returnValue(new CanonicalUser("unitTest")));
		mockHttpServletRequest.expects(once()).method("getHeader").with(
				eq("x-hack-user")).will(returnValue(null));

		try {
			HackAuthenticator authenticator = new HackAuthenticator();
			authenticator.setAuthenticator(new S3Authenticator());

			o = S3ObjectRequest.create(
					(HttpServletRequest) mockHttpServletRequest.proxy(),
					"s3.amazonaws.com", authenticator);
		} catch (IllegalArgumentException e) {
			e.printStackTrace();
			fail("Unexpected exception");
			return;
		} catch (AuthenticatorException e) {
			e.printStackTrace();
			fail("Unexpected exception");
			return;
		}

		assertEquals("Unexpected serviceEndpoint", "http://s3.amazonaws.com", o
				.getServiceEndpoint());
		assertEquals("Unexpected bucket", "johnsmith", o.getBucket());
		assertEquals("Unexpected key", "homepage.html", o.getKey());
	}

	/**
	 * Test a <code>create</code> using virtual hosting of buckets. Sub-domain
	 * method.
	 */
	public void xtest_virtualHostingSubDomain() {
		S3ObjectRequest o;
		Mock mockHttpServletRequest = mock(HttpServletRequest.class);

		mockHttpServletRequest.expects(once()).method("getPathInfo").will(
				returnValue("/homepage.html"));
		mockHttpServletRequest.expects(once()).method("getRequestURL").will(
				returnValue(new StringBuffer(
						"http://johnsmith.s3.amazonaws.com/homepage.html")));
		mockHttpServletRequest.expects(once()).method("getHeader").with(
				eq("Host")).will(returnValue("johnsmith.s3.amazonaws.com"));
		mockHttpServletRequest.expects(once()).method("getUserPrincipal").will(
				returnValue(new CanonicalUser("unitTest")));
		mockHttpServletRequest.expects(once()).method("getHeader").with(
				eq("x-hack-user")).will(returnValue(null));

		try {
			HackAuthenticator authenticator = new HackAuthenticator();
			authenticator.setAuthenticator(new S3Authenticator());

			o = S3ObjectRequest.create(
					(HttpServletRequest) mockHttpServletRequest.proxy(),
					"s3.amazonaws.com", authenticator);
		} catch (IllegalArgumentException e) {
			e.printStackTrace();
			fail("Unexpected exception");
			return;
		} catch (AuthenticatorException e) {
			e.printStackTrace();
			fail("Unexpected exception");
			return;
		}

		assertEquals("Unexpected serviceEndpoint",
				"http://johnsmith.s3.amazonaws.com", o.getServiceEndpoint());
		assertEquals("Unexpected bucket", "johnsmith", o.getBucket());
		assertEquals("Unexpected key", "homepage.html", o.getKey());
	}

	/**
	 * Test a <code>create</code> using virtual hosting of buckets. Sub-domain
	 * method with upper case Host header.
	 */
	public void xtest_virtualHostingSubDomainUpperCase() {
		S3ObjectRequest o;
		Mock mockHttpServletRequest = mock(HttpServletRequest.class);

		mockHttpServletRequest.expects(once()).method("getPathInfo").will(
				returnValue("/homepage.html"));
		mockHttpServletRequest.expects(once()).method("getRequestURL").will(
				returnValue(new StringBuffer(
						"http://johnsmith.s3.amazonaws.com/homepage.html")));
		mockHttpServletRequest.expects(once()).method("getHeader").with(
				eq("Host")).will(returnValue("JohnSmith.s3.amazonaws.com"));
		mockHttpServletRequest.expects(once()).method("getUserPrincipal").will(
				returnValue(new CanonicalUser("unitTest")));
		mockHttpServletRequest.expects(once()).method("getHeader").with(
				eq("x-hack-user")).will(returnValue(null));

		try {
			HackAuthenticator authenticator = new HackAuthenticator();
			authenticator.setAuthenticator(new S3Authenticator());

			o = S3ObjectRequest.create(
					(HttpServletRequest) mockHttpServletRequest.proxy(),
					"s3.amazonaws.com", authenticator);
		} catch (IllegalArgumentException e) {
			e.printStackTrace();
			fail("Unexpected exception");
			return;
		} catch (AuthenticatorException e) {
			e.printStackTrace();
			fail("Unexpected exception");
			return;
		}

		assertEquals("Unexpected serviceEndpoint",
				"http://johnsmith.s3.amazonaws.com", o.getServiceEndpoint());
		assertEquals("Unexpected bucket", "johnsmith", o.getBucket());
		assertEquals("Unexpected key", "homepage.html", o.getKey());
	}

	/**
	 * Test a <code>create</code> using virtual hosting of buckets. Domain is
	 * the bucket.
	 */
	public void xtest_virtualHostingDomain() {
		S3ObjectRequest o;
		Mock mockHttpServletRequest = mock(HttpServletRequest.class);

		mockHttpServletRequest.expects(once()).method("getPathInfo").will(
				returnValue("/homepage.html"));
		mockHttpServletRequest.expects(once()).method("getRequestURL").will(
				returnValue(new StringBuffer(
						"http://www.johnsmith.net/homepage.html")));
		mockHttpServletRequest.expects(once()).method("getHeader").with(
				eq("Host")).will(returnValue("www.johnsmith.net"));
		mockHttpServletRequest.expects(once()).method("getUserPrincipal").will(
				returnValue(new CanonicalUser("unitTest")));
		mockHttpServletRequest.expects(once()).method("getHeader").with(
				eq("x-hack-user")).will(returnValue(null));

		try {
			HackAuthenticator authenticator = new HackAuthenticator();
			authenticator.setAuthenticator(new S3Authenticator());

			o = S3ObjectRequest.create(
					(HttpServletRequest) mockHttpServletRequest.proxy(),
					"s3.amazonaws.com", authenticator);
		} catch (IllegalArgumentException e) {
			e.printStackTrace();
			fail("Unexpected exception");
			return;
		} catch (AuthenticatorException e) {
			e.printStackTrace();
			fail("Unexpected exception");
			return;
		}

		assertEquals("Unexpected serviceEndpoint", "http://www.johnsmith.net",
				o.getServiceEndpoint());
		assertEquals("Unexpected bucket", "www.johnsmith.net", o.getBucket());
		assertEquals("Unexpected key", "homepage.html", o.getKey());
	}

	/**
	 * Test a <code>create</code> with no key but and no slash character after
	 * the bucket.
	 */
	public void xtest_createNoKeyBucketNoSlash() {
		S3ObjectRequest o;
		Mock mockHttpServletRequest = mock(HttpServletRequest.class);

		mockHttpServletRequest.expects(once()).method("getPathInfo").will(
				returnValue("/myBucket"));
		mockHttpServletRequest.expects(once()).method("getHeader").with(
				eq("Host")).will(returnValue("localhost"));
		mockHttpServletRequest.expects(once()).method("getRequestURL").will(
				returnValue(new StringBuffer(
						"http://localhost/context/myBucket")));
		mockHttpServletRequest.expects(once()).method("getUserPrincipal").will(
				returnValue(new CanonicalUser("unitTest")));
		mockHttpServletRequest.expects(once()).method("getHeader").with(
				eq("x-hack-user")).will(returnValue(null));

		try {
			HackAuthenticator authenticator = new HackAuthenticator();
			authenticator.setAuthenticator(new S3Authenticator());

			o = S3ObjectRequest.create(
					(HttpServletRequest) mockHttpServletRequest.proxy(),
					"localhost", authenticator);
		} catch (IllegalArgumentException e) {
			e.printStackTrace();
			fail("Unexpected exception");
			return;
		} catch (AuthenticatorException e) {
			e.printStackTrace();
			fail("Unexpected exception");
			return;
		}

		assertEquals("Unexpected serviceEndpoint", "http://localhost/context",
				o.getServiceEndpoint());
		assertEquals("Unexpected bucket", "myBucket", o.getBucket());
		assertNull("Unexpected key", o.getKey());
	}

	/**
	 * Test a <code>create</code> with no bucket.
	 */
	public void xtest_createNoBucket() {
		S3ObjectRequest o;
		Mock mockHttpServletRequest = mock(HttpServletRequest.class);

		mockHttpServletRequest.expects(once()).method("getPathInfo").will(
				returnValue("/"));
		mockHttpServletRequest.expects(once()).method("getHeader").with(
				eq("Host")).will(returnValue("localhost"));
		mockHttpServletRequest.expects(once()).method("getRequestURL").will(
				returnValue(new StringBuffer("http://localhost/context/")));
		mockHttpServletRequest.expects(once()).method("getUserPrincipal").will(
				returnValue(new CanonicalUser("unitTest")));
		mockHttpServletRequest.expects(once()).method("getHeader").with(
				eq("x-hack-user")).will(returnValue(null));

		try {
			HackAuthenticator authenticator = new HackAuthenticator();
			authenticator.setAuthenticator(new S3Authenticator());

			o = S3ObjectRequest.create(
					(HttpServletRequest) mockHttpServletRequest.proxy(),
					"localhost", authenticator);
		} catch (IllegalArgumentException e) {
			e.printStackTrace();
			fail("Unexpected exception");
			return;
		} catch (AuthenticatorException e) {
			e.printStackTrace();
			fail("Unexpected exception");
			return;
		}

		assertEquals("Unexpected serviceEndpoint", "http://localhost/context",
				o.getServiceEndpoint());
		assertNull("Unexpected bucket", o.getBucket());
		assertNull("Unexpected key", o.getKey());
	}

	/**
	 * Test a <code>create</code> with an invalid request.
	 */
	public void xtest_createIllegalRequest() {
		Mock mockHttpServletRequest = mock(HttpServletRequest.class);

		mockHttpServletRequest.expects(once()).method("getPathInfo").will(
				returnValue("/foo"));
		mockHttpServletRequest.expects(once()).method("getHeader").with(
				eq("Host")).will(returnValue("localhost"));
		mockHttpServletRequest.expects(once()).method("getRequestURL").will(
				returnValue(new StringBuffer("http://localhost/context/bar")));

		try {
			HackAuthenticator authenticator = new HackAuthenticator();
			authenticator.setAuthenticator(new S3Authenticator());

			S3ObjectRequest.create((HttpServletRequest) mockHttpServletRequest
					.proxy(), "localhost", authenticator);
			fail("Expected exception");
		} catch (IllegalArgumentException e) {
			// expected
		} catch (AuthenticatorException e) {
			e.printStackTrace();
			fail("Unexpected exception");
			return;
		}
	}

	/**
	 * Basically a utility test for creating an ISO 8601 date.
	 */
	public void test_isoDate() {
		SimpleDateFormat iso8601 = new SimpleDateFormat(
				"yyyy-MM-dd'T'HH:mm:ss.SSS'Z'");
		TimeZone utc = TimeZone.getTimeZone("UTC");
		iso8601.setTimeZone(utc);

		GregorianCalendar cal = new GregorianCalendar(2007, 6, 19, 9, 50, 33);

		assertEquals("Unexpected formatted date", "2007-07-19T07:50:33.000Z",
				iso8601.format(cal.getTime()));
	}

	/**
	 * Integration test to execute the algorithm for hostname resolution.
	 */
	public void xtest_localHost() {
		String configHost;
		String token = "$resolvedLocalHost$";

		configHost = "foo:" + token + token + ":8080";

		if (configHost.indexOf(token) >= 0) {
			InetAddress localHost;
			String resolvedLocalHost = "localhost";

			try {
				localHost = InetAddress.getLocalHost();
				resolvedLocalHost = localHost.getCanonicalHostName();
			} catch (UnknownHostException e) {
				logger.fatal("Unable to resolve local host", e);
			}

			configHost = configHost.replace(token, resolvedLocalHost);
		}

		// this is machine dependent
		System.out.println(">>>> configHost: " + configHost);
		assertEquals("Unexpected hostname",
				"foo:PEM32Z2RC1LIC.NCSP.PEROOT.COMPEM32Z2RC1LIC.NCSP.PEROOT.COM:8080", configHost);
	}
}
