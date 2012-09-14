/*
 * Copyright 2012 s0525775 / DESY.
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
import java.util.ArrayList;

/**
 *
 * @author s0525775
 */
public class DatabaseUser {

    public DatabaseUser () {
    }
    
    public String getUserId(String accessKeyId) {
        String userId = "";
        DatabaseConnection dbconn = new DatabaseConnection();
        dbconn.connect();
        ArrayList fetchDB = dbconn.fetchDataByAccessKeyId(accessKeyId);
        userId = fetchDB.get(7).toString();
        
        dbconn.disconnect();        
        return userId;
    }
    
    public String getUserName(String accessKeyId) {
        String userName = "";
        DatabaseConnection dbconn = new DatabaseConnection();
        dbconn.connect();
        ArrayList fetchDB = dbconn.fetchDataByAccessKeyId(accessKeyId);
        userName = fetchDB.get(7).toString();
        
        dbconn.disconnect();        
        return userName;
    }

    public String getDisplayName(String accessKeyId) {
        String displayName = "";
        DatabaseConnection dbconn = new DatabaseConnection();
        dbconn.connect();
        ArrayList fetchDB = dbconn.fetchDataByAccessKeyId(accessKeyId);
        displayName = fetchDB.get(7).toString();
        
        dbconn.disconnect();        
        return displayName;
    }

    public String getEMail(String accessKeyId) {
        String eMail = "";
        DatabaseConnection dbconn = new DatabaseConnection();
        dbconn.connect();
        ArrayList fetchDB = dbconn.fetchDataByAccessKeyId(accessKeyId);
        eMail = fetchDB.get(7).toString();
        
        dbconn.disconnect();        
        return eMail;
    }

    public String getPassword(String accessKeyId) {
        String password = "";
        DatabaseConnection dbconn = new DatabaseConnection();
        dbconn.connect();
        ArrayList fetchDB = dbconn.fetchDataByAccessKeyId(accessKeyId);
        password = fetchDB.get(7).toString();
        
        dbconn.disconnect();        
        return password;
    }

    public String getAWSSecretAccessKey(String accessKeyId) {
        String secretAccessKey = "";
        DatabaseConnection dbconn = new DatabaseConnection();
        dbconn.connect();
        ArrayList fetchDB = dbconn.fetchDataByAccessKeyId(accessKeyId);
        secretAccessKey = fetchDB.get(7).toString();
        
        dbconn.disconnect();        
        return secretAccessKey;
    }
}
