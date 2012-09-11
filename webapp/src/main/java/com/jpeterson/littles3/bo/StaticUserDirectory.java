package com.jpeterson.littles3.bo;

/**
 * Static implementation of <code>UserDirectory</code> that will return the same
 * AWSSecretAccessKey for any AWSAccessKeyId.
 * 
 * @author Jesse Peterson
 */
public class StaticUserDirectory implements UserDirectory {

	public StaticUserDirectory() {

	}

	public String getAwsSecretAccessKey(String awsAccessKeyId) {
            
            if (awsAccessKeyId.equals("AKIAJ2FBI53FU5ECPSUR")) {
		return "aGJSBPY5Cbafhb5UPKlbNRluXlFj9JIVqFx103w2";
            } else if (awsAccessKeyId.equals("1000")) {
		return "xpivpiuo";
            } else {
                return null;
            }
            
	}

	public CanonicalUser getCanonicalUser(String awsAccessKeyId) {
		CanonicalUser user;

		user = new CanonicalUser(awsAccessKeyId);
		user.setDisplayName("Anonymous");
		return user;
	}
}
