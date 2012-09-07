/*
 * Copyright 2012 s0525775 / DESY.
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
package de.desy.dcache.s3.db;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.ArrayList;

/*
 * CREATE TABLE awsuser (
 * UserID SERIAL NOT NULL, 
 * UserEMail VARCHAR(255) NOT NULL, 
 * UserName VARCHAR(50) NOT NULL, 
 * DisplayName VARCHAR(255) NOT NULL, 
 * Password VARCHAR(50) NOT NULL, 
 * AccessKeyId CHAR(20) NOT NULL, 
 * SecretAccessKey CHAR(40) NOT NULL, 
 * PRIMARY KEY (UserID), 
 * UNIQUE (UserID), 
 * UNIQUE (UserEMail), 
 * UNIQUE (AccessKeyId), 
 * UNIQUE (SecretAccessKey)
 * );
 * 
 * TODO: Password is not encrypted in the database till now.
 * AccessKeyId and SecretAccessKey could be encrypted later, too.
 * For example, via MD5.
 */

/**
 *
 * @author s0525775
 */
public class DatabaseConnection {
    
    private Connection connection = null;
    private String connectionString = "";
    private String dbuser = "";
    private String dbpassword = "";
    private String dbtable = "";
    private String dbaccesskeyidrow = "";
    private String dbusernamerow = "";
    private String dbuseremailrow = "";
    
    public DatabaseConnection() {
        connectionString = "jdbc:postgresql://127.0.0.1:5432/awsuser";
        dbuser = "awsuser";
        dbpassword = "awsuser";
        dbtable = "awsuser";
        dbaccesskeyidrow = "AccessKeyId";
        dbusernamerow = "SecretAccessKey";
        dbuseremailrow = "UserEMail";
    }
    
    /**
     * 
     * @return 
     */
    public Connection connect() {
        try {
            connection = null;
            Class.forName("org.postgresql.Driver");  
            connection = DriverManager.getConnection(connectionString, dbuser, dbpassword);
            return connection;
        } catch(Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * 
     * @param connectionString
     * @param dbuser
     * @param dbpassword
     * @return 
     */
    public Connection connect(String connectionString, String dbuser, String dbpassword) {
        this.connectionString = connectionString;
        this.dbuser = dbuser;
        this.dbpassword = dbpassword;
        try {
            connection = null;
            Class.forName("org.postgresql.Driver");  
            connection = DriverManager.getConnection(this.connectionString, this.dbuser, this.dbpassword);
            return connection;
        } catch(Exception e) {
            e.printStackTrace();
            return null;
        }
    }
    
    /**
     * 
     * @return 
     */
    public boolean disconnect() {
        if (connection != null) {
            try {
                connection.close();
                connection = null;
                return true;
            } catch(Exception e) {
                e.printStackTrace();
                return false;
            }
        } else {
            return false;
        }
    }
    
    /**
     * 
     * @param AccessKeyId
     * @return 
     */
    public ArrayList fetchDataByAccessKeyId(String AccessKeyId) {
        ArrayList result = new ArrayList();
        result.clear();
        if (connection != null) {
            try {
                String query = "SELECT * FROM " + dbtable + " WHERE " + dbaccesskeyidrow + "='" + AccessKeyId + "'";
                Statement stmt = connection.createStatement(); 
                ResultSet rs = stmt.executeQuery(query);
                while(rs.next()) {
                    for (int i = 1; i < 8; i++) {
                        result.add(rs.getString(i));
                    }
                }
                rs.close();
                stmt.close();
            } catch(Exception e) {
                e.printStackTrace();
            }
        }
        return result;
    }

    /**
     * 
     * @param dbtable
     * @param dbaccesskeyidrow
     * @param AccessKeyId
     * @return 
     */
    public ArrayList fetchDataByAccessKeyId(String dbtable, String dbaccesskeyidrow, String AccessKeyId) {
        ArrayList result = new ArrayList();
        result.clear();
        this.dbtable = dbtable;
        this.dbaccesskeyidrow = dbaccesskeyidrow;
        if (connection != null) {
            try {
                String query = "SELECT * FROM " + dbtable + " WHERE " + this.dbaccesskeyidrow + "='" + AccessKeyId + "'";
                Statement stmt = connection.createStatement(); 
                ResultSet rs = stmt.executeQuery(query);
                while(rs.next()) {
                    for (int i = 1; i < 8; i++) {
                        result.add(rs.getString(i));
                    }
                }
                rs.close();
                stmt.close();
            } catch(Exception e) {
                e.printStackTrace();
            }
        }
        return result;
    }
    
    /**
     * 
     * @param userName
     * @return 
     */
    public ArrayList fetchDataByUserName(String userName) {
        ArrayList result = new ArrayList();
        result.clear();
        if (connection != null) {
            try {
                String query = "SELECT * FROM " + dbtable + " WHERE " + dbusernamerow + "=" + userName;
                Statement stmt = connection.createStatement(); 
                ResultSet rs = stmt.executeQuery(query);
                while(rs.next()) {
                    for (int i = 1; i < 8; i++) {
                        result.add(rs.getString(i));
                    }
                }
                rs.close();
                stmt.close();
            } catch(Exception e) {
                e.printStackTrace();
            }
        }
        return result;
    }

    /**
     * 
     * @param dbtable
     * @param dbusernamerow
     * @param userName
     * @return 
     */
    public ArrayList fetchDataByUserName(String dbtable, String dbusernamerow, String userName) {
        ArrayList result = new ArrayList();
        result.clear();
        this.dbtable = dbtable;
        this.dbusernamerow = dbusernamerow;
        if (connection != null) {
            try {
                String query = "SELECT * FROM " + dbtable + " WHERE " + this.dbusernamerow + "=" + userName;
                Statement stmt = connection.createStatement(); 
                ResultSet rs = stmt.executeQuery(query);
                while(rs.next()) {
                    for (int i = 1; i < 8; i++) {
                        result.add(rs.getString(i));
                    }
                }
                rs.close();
                stmt.close();
            } catch(Exception e) {
                e.printStackTrace();
            }
        }
        return result;
    }

    /**
     * 
     * @param userEMail
     * @return 
     */
    public ArrayList fetchDataByUserEMail(String userEMail) {
        ArrayList result = new ArrayList();
        result.clear();
        if (connection != null) {
            try {
                String query = "SELECT * FROM " + dbtable + " WHERE " + dbuseremailrow + "=" + userEMail.toLowerCase();
                Statement stmt = connection.createStatement(); 
                ResultSet rs = stmt.executeQuery(query);
                while(rs.next()) {
                    for (int i = 1; i < 8; i++) {
                        result.add(rs.getString(i));
                    }
                }
                rs.close();
                stmt.close();
            } catch(Exception e) {
                e.printStackTrace();
            }
        }
        return result;
    }

    /**
     * 
     * @param dbtable
     * @param dbuseremailrow
     * @param userEMail
     * @return 
     */
    public ArrayList fetchDataByUserEMail(String dbtable, String dbuseremailrow, String userEMail) {
        ArrayList result = new ArrayList();
        result.clear();
        this.dbtable = dbtable;
        this.dbuseremailrow = dbuseremailrow;
        if (connection != null) {
            try {
                String query = "SELECT * FROM " + dbtable + " WHERE " + this.dbuseremailrow + "=" + userEMail.toLowerCase();
                Statement stmt = connection.createStatement(); 
                ResultSet rs = stmt.executeQuery(query);
                while(rs.next()) {
                    for (int i = 1; i < 8; i++) {
                        result.add(rs.getString(i));
                    }
                }
                rs.close();
                stmt.close();
            } catch(Exception e) {
                e.printStackTrace();
            }
        }
        return result;
    }

    /**
     * 
     * @return 
     */
    private boolean _fetchDBInformationFromProperties() {
        //todo: get all DB information from StorageEngine.properties.
        connectionString = "jdbc:postgresql://127.0.0.1:5432/awsuser";
        dbuser = "awsuser";
        dbpassword = "awsuser";
        dbtable = "awsuser";
        dbaccesskeyidrow = "AccessKeyId";
        dbusernamerow = "SecretAccessKey";
        dbuseremailrow = "UserEMail";
        return false;
    }
    
}
