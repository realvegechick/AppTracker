package fudan.secsys.apptracker;
import java.sql.*;

public class Database {
    static final String JDBC_DRIVER = "com.mysql.cj.jdbc.Driver";
    static final String DB_URL = "jdbc:mysql://10.177.83.229:3306/log";
    // static final String DB_URL = "jdbc:mysql://DESKTOP-8BHQG8P/log";

    static final String USER = "root";
    static final String PASS = "zzz123456.";

    public static void insert(String serviceName, String methodName, String parameters, int callingUid, int callingPid) throws Exception {
        Connection conn = null;
        PreparedStatement stmt = null;
        try {
            // 注册 JDBC 驱动器
            Class.forName("com.mysql.cj.jdbc.Driver");

            // 打开连接
            //System.out.println("Connecting to database...");
            conn = DriverManager.getConnection(DB_URL, USER, PASS);

            // 执行sql语句
            //System.out.println("Creating statement...");
            String sql = "INSERT into loginfo value(?,?,?,?,?);";
            stmt = conn.prepareStatement(sql);

            // 参数赋值，参数从左至右序号为 1，2...
            stmt.setString(1, serviceName);
            stmt.setString(2, methodName);
            stmt.setString(3, parameters);
            stmt.setInt(4, callingUid);
            stmt.setInt(5, callingPid);

            //执行sql语句，返回类型为int，代表操作的数据条数
            int rows = stmt.executeUpdate();// int executeUpdate(String SQL)
            //System.out.println("被影响的行数 : " + rows);

            /*
             * sql = "SELECT id, name, age FROM info";
             * ResultSet rs = stmt.executeQuery(sql);// 执行查询操作时使用此方法可以生成一个Resultset集合
             *
             * while (rs.next()) {
             * int id = rs.getInt("id");
             * int age = rs.getInt("age");
             * String name = rs.getString("name");
             *
             * System.out.print("ID: " + id);
             * System.out.print(", Age: " + age);
             * System.out.print(", Name: " + name);
             * System.out.println();
             * }
             * rs.close();
             */

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
        //System.out.println("Goodbye!");
    }
}
