package com.jpeterson.littles3.bo;

import org.apache.commons.configuration.Configuration;
import org.apache.commons.configuration.ConfigurationException;
import org.apache.commons.configuration.PropertiesConfiguration;
import org.apache.commons.logging.Log;

/**
 * Static implementation of <code>UserDirectory</code> that will return the same
 * AWSSecretAccessKey for any AWSAccessKeyId.
 * try to replace by de.desy.dcache.s3.DatabaseUser later.
 * 
 * @author Jesse Peterson, changed by s0525775 / DESY
 */
public class StaticUserDirectory implements UserDirectory {

        private Log logger;
    
        public static final String DEFAULT_DIRECTORY = "UserDirectory.properties"; 
        
        private Configuration directory;
    
	public StaticUserDirectory() {
            try {
                directory = new PropertiesConfiguration(DEFAULT_DIRECTORY);
            } catch (ConfigurationException e) {
                logger
                    .warn("Unable to load default properties-based directory: "
                            + DEFAULT_DIRECTORY);
                directory = new PropertiesConfiguration();
            }
	}

        /**
         * 
         * @param awsAccessKeyId
         * @return 
         */
	public String getAwsSecretAccessKey(String awsAccessKeyId) {
            
            if (awsAccessKeyId != null && !awsAccessKeyId.isEmpty()) {
                return directory.getString("SK_" + awsAccessKeyId);
            } else {
                return null;
            }
            
	}

        /**
         * 
         * @param awsAccessKeyId
         * @return 
         */
        public CanonicalUser getCanonicalUser(String awsAccessKeyId) {
            
            return new CanonicalUser(awsAccessKeyId);
        }

}
