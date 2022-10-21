package fudan.secsys.apptracker;
import android.app.Activity;
import android.app.ActivityManager;
import android.util.Log;
import android.content.Context;

import java.sql.*;
import java.util.List;

public class Database {
    static final String JDBC_DRIVER = "com.mysql.jdbc.Driver";
    //设备和数据库须在同一网络下
    static final String DB_URL = "jdbc:mysql://10.177.83.229:3306/log";
    //static final String DB_URL = "jdbc:mysql://192.168.251.179:3306/log";


    static final String USER = "root";
    static final String PASS = "zzz123456.";

    public static void createTab(String tabName){
        Connection conn = null;
        PreparedStatement stmt = null;

        try {
            // 注册 JDBC 驱动器
            Class.forName(JDBC_DRIVER);
            //Log.d("InteractingDatabase","START INSERT!!!");

            // 打开连接
            conn = DriverManager.getConnection(DB_URL, USER, PASS);
            //Log.d("InteractingDatabase","CONNECTED WITH DATABASE!!!");

            // 创建数据表
            String createTabSql = "CREATE TABLE " + tabName + "(timeStamp long, callingPid int, serviceName varchar(50), methodName varchar(50), parameters varchar(1024));";

            stmt = conn.prepareStatement(createTabSql);
            stmt.executeUpdate();

            stmt.close();
            conn.close();
        } catch (SQLException se) {
            se.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        } finally {// 关闭资源
            try {
                if (stmt != null)
                    stmt.close();
            } catch (SQLException se2) {
            }
            try {
                if (conn != null)
                    conn.close();
            } catch (SQLException se) {
                se.printStackTrace();
            }
        }
    }

    public static void insert(String tabName, long timeStamp, String serviceName, String methodName, String parameters, int callingPid) throws Exception {
        Connection conn = null;
        PreparedStatement stmt = null;

        try {
            // 注册 JDBC 驱动器
            Class.forName(JDBC_DRIVER);
            //Log.d("InteractingDatabase","START INSERT!!!");

            // 打开连接
            conn = DriverManager.getConnection(DB_URL, USER, PASS);
            //Log.d("InteractingDatabase","CONNECTED WITH DATABASE!!!");

            // 执行sql语句
            String sql = "INSERT into " + tabName + " value(?,?,?,?,?);";
            stmt = conn.prepareStatement(sql);

            // 参数赋值，参数从左至右序号为 1，2...
            stmt.setLong(1, timeStamp);
            stmt.setInt(2, callingPid);
            stmt.setString(3, serviceName);
            stmt.setString(4, methodName);
            stmt.setString(5, parameters);


            //执行sql语句，返回类型为int，代表操作的数据条数
            stmt.executeUpdate();// int executeUpdate(String SQL)
            //Log.d("InteractingDatabase","FINISH INSERT!!!");

            stmt.close();
            conn.close();
        } catch (SQLException se) {
            se.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        } finally {// 关闭资源
            try {
                if (stmt != null)
                    stmt.close();
            } catch (SQLException se2) {
            }
            try {
                if (conn != null)
                    conn.close();
            } catch (SQLException se) {
                se.printStackTrace();
            }
        }
    }
    public static void dropTab(String tabName){
        Connection conn = null;
        PreparedStatement stmt = null;

        try {
            // 注册 JDBC 驱动器
            Class.forName(JDBC_DRIVER);
            //Log.d("InteractingDatabase","START INSERT!!!");

            // 打开连接
            conn = DriverManager.getConnection(DB_URL, USER, PASS);
            //Log.d("InteractingDatabase","CONNECTED WITH DATABASE!!!");

            // 删除数据表
            String dropTabSql = "DROP table " + tabName + ";";
            stmt = conn.prepareStatement(dropTabSql);
            stmt.executeUpdate();

            stmt.close();
            conn.close();
        } catch (SQLException se) {
            se.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        } finally {// 关闭资源
            try {
                if (stmt != null)
                    stmt.close();
            } catch (SQLException se2) {
            }
            try {
                if (conn != null)
                    conn.close();
            } catch (SQLException se) {
                se.printStackTrace();
            }
        }
    }
}
