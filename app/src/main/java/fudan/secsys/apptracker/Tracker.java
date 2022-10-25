package fudan.secsys.apptracker;

import android.app.ActivityManager;
import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.util.Log;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.ServerSocket;
import java.net.Socket;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import java.util.Locale;

public class Tracker {
    static class LogThread extends Thread {
        int flag = 1;
        static private String pkgName;

        public LogThread(String app_name) {
            pkgName = app_name;
        }

        public void run() {
            try {
                Process process = Runtime.getRuntime().exec("logcat");
                InputStream is = process.getInputStream();
                BufferedReader br = new BufferedReader(new InputStreamReader(is));
                String line;
                //创建数据表
                DBOpenHelper dbOpenHelper = new DBOpenHelper(MyApplication.getContext(), "log.db",null, 1);
                SQLiteDatabase db = dbOpenHelper.getWritableDatabase();


                //SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.CHINA);
                Date date = new Date(System.currentTimeMillis());
                String tabname= "`"+pkgName+" "+date+" Log`";
             //   Database.createLog(tabname);
                String createTabSql = "CREATE TABLE " + tabname + "(timeStamp long, callingPid int, serviceName varchar(50), methodName varchar(50), parameters varchar(1024))";
                db.execSQL(createTabSql);
                boolean isEmptyTab = true;

                while ((line = br.readLine()) != null && flag==1) {
                    if(line.contains("Maldetect") && !line.contains("zzzzzzz")) {
                        int index=0;

                        int callingPid=0;
                        try {
                            int callingUid = Integer.parseInt(line.substring(line.indexOf("callingUid:") + "callingUid:".length(),
                                    index = line.indexOf(",")));
                            callingPid = Integer.parseInt(line.substring(line.indexOf("callingPid:") + "callingPid:".length(),
                                    index = line.indexOf(",", index + 1)));
                        }catch (Exception e){
                            Log.d("zzzzzzz", line);
                            e.printStackTrace();
                        }

                        //获取包名
                        String callingPkgName = "";
                        ActivityManager activityManager = (ActivityManager) MyApplication.getContext().getSystemService(Context.ACTIVITY_SERVICE);
                        if (activityManager != null) {
                            List<ActivityManager.RunningAppProcessInfo> list = activityManager.getRunningAppProcesses();
                            for (ActivityManager.RunningAppProcessInfo info : list) {
                                if (info.pid == callingPid) {
                                    callingPkgName = info.processName;
                                    break;
                                }
                            }
                        }
                        //if (line.contains("AppTracker") && (!line.contains("MaldectTest"))) {
                        if (callingPkgName.contains(pkgName)) {
                            //Todo: SQLite
                            int space = line.indexOf(" ");
                            space = line.indexOf(" ", space + 1);
                            String formatTime = "2022-" + line.substring(0, space);
                            SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyy-MM-dd hh:mm:ss.SSS",Locale.CHINA);
                            long timeStamp = 0;
                            try{
                                date = simpleDateFormat.parse(formatTime);
                                timeStamp = date.getTime();
                            } catch (Exception e) {
                                e.printStackTrace();
                            }

                            String serviceName = line.substring(index + 1,
                                    index = line.indexOf(".", index + 1));
                            String methodName = line.substring(index + 1,
                                    index = line.indexOf("(", index + 1));
                            String parameters = null;
                            if (line.indexOf(")", index + 1) - (index+1) > 1){
                                parameters = line.substring(index + 1,
                                        line.indexOf(")", index + 1));
                            }

                            long finalTimeStamp = timeStamp;
                            String finalParameters = parameters;
                         //   Database.insertLog(tabname, finalTimeStamp, serviceName, methodName, finalParameters, callingPid);
                            ContentValues values = new ContentValues();
                            values.put("timeStamp", finalTimeStamp);
                            values.put("callingPid", callingPid);
                            values.put("serviceName", serviceName);
                            values.put("methodName", methodName);
                            values.put("parameters", finalParameters);
                            db.insert(tabname, null, values);
                            isEmptyTab = false;

                        }
                    }
                }
                //删除空表
                if(isEmptyTab){
                //    Database.dropTab(tabname);
                    db.execSQL("drop table "+ tabname);
                }
                db.close();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }
    static class BPFThread extends Thread {
        int flag = 1;
        static private String pkgName;

        public BPFThread(String app_name) {
            pkgName = app_name;
        }
        public void run() {
            try {
                ServerSocket s = new ServerSocket(23334);
                Socket server=s.accept();
                InputStream is = server.getInputStream();
                BufferedReader br = new BufferedReader(new InputStreamReader(is));
                String line;
                Date date = new Date(System.currentTimeMillis());
                String tabname= "`"+pkgName+" "+date+" BPF`";
                //Database.createBPF(tabname);
                DBOpenHelper dbOpenHelper = new DBOpenHelper(MyApplication.getContext(), "log.db",null, 1);
                SQLiteDatabase db = dbOpenHelper.getWritableDatabase();
                String createTabSql = "CREATE TABLE " + tabname + "(timeStamp long, callingPid long, syscall varchar(10), parameters varchar(200), str varchar(256), ret long)";
                db.execSQL(createTabSql);
                boolean isEmptyTab = true;

                while ((line = br.readLine()) != null && flag==1) {
                    if(line.contains(pkgName)) {
                        String[] str_array=line.split(", ");
                        final String syscall,str;
                        final long time,pid,ret;
                        double args[]=new double[6];
                        if(str_array.length>5){//sys_enter
                            time=Long.parseLong(str_array[0]);
                            pid=Long.parseLong(str_array[2]);
                            syscall=str_array[3];
                            args[0]=Double.parseDouble(str_array[4]);
                            args[1]=Double.parseDouble(str_array[5]);
                            args[2]=Double.parseDouble(str_array[6]);
                            args[3]=Double.parseDouble(str_array[7]);
                            args[4]=Double.parseDouble(str_array[8]);
                            args[5]=Double.parseDouble(str_array[9]);
                            if(str_array.length>10)
                                str=str_array[10];
                            else
                                str=null;
                            //line="time:"+time+", app:"+app+", pid:"+pid+", syscall:"+syscall+", arg0:"+arg0+", arg1:"+arg1+", arg2:"+arg2+", arg3:"+arg3+", arg4:"+arg4+", arg5:"+arg5+", str:"+str;
                            //Log.d("MaldectTest.BPF",line);
                            //Database.insertBPF(tabname, time, pid, syscall, args.toString(), str, -2147483648, false);
                            ContentValues values = new ContentValues();
                            values.put("timeStamp", time);
                            values.put("callingPid", pid);
                            values.put("syscall", syscall);
                            values.put("parameters",String.valueOf(args[0])+","+String.valueOf(args[1])+","+String.valueOf(args[2])+","+String.valueOf(args[3])+","+String.valueOf(args[4])+","+String.valueOf(args[5]));
                            values.put("str", str);
                            values.put("ret", -2147483648);
                            db.insert(tabname, null, values);
                            isEmptyTab = false;
                        }
                        else{//sys_exit
                            time=Long.parseLong(str_array[0]);
                            pid=Long.parseLong(str_array[2]);
                            syscall=str_array[3];
                            ret=Long.parseLong(str_array[4]);
                            //line="time:"+time+", app:"+app+", pid:"+pid+", syscall:"+syscall+", ret:"+ret;
                            //Log.d("MaldectTest.BPF",line);
                            //Database.insertBPF(tabname, time, pid, syscall, null, null, ret, true);

                            String querySql = "SELECT * FROM " + tabname + " WHERE callingPid=? AND syscall=? AND ret=? ORDER BY timeStamp";
                            Cursor cursor = db.rawQuery(querySql, new String[]{String.valueOf(pid), syscall ,String.valueOf(-2147483648)});
                            cursor.moveToFirst();
                            if(!cursor.isAfterLast()){
                                long o_time = cursor.getLong(0);
                                if(o_time<time){
                                    String sql = "UPDATE "+tabname+" SET ret=? WHERE timeStamp=? AND callingPid=? AND syscall=?";
                                    db.execSQL(sql, new Object[]{ret, o_time, pid, syscall});
                                }
                            }
                            cursor.close();
                            isEmptyTab = false;

                        }
                    }
                }
                //删除空表
                if(isEmptyTab){
                    //Database.dropTab(tabname);
                    db.execSQL("drop table "+ tabname);
                }
                db.close();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }
    static LogThread t_log;
    static BPFThread t_bpf;
    static void startTrack(String app_name){
        t_log=new LogThread(app_name);
        t_log.flag=1;
        t_log.start();
        t_bpf=new BPFThread(app_name);
        t_bpf.flag=1;
        t_bpf.start();
    }
    static void stopTrack() {
        String oldpath = "/data/data/fudan.secsys.apptracker/databases/log.db";
        String newpath = "/sdcard/database/log.db";
        try{
            File oldfile = new File(oldpath);
            if (oldfile.exists() && oldfile.isFile() && oldfile.canRead()) {
                FileInputStream fileInputStream = new FileInputStream(oldpath);
                FileOutputStream fileOutputStream = new FileOutputStream(newpath);
                byte[] buffer = new byte[1024];
                int byteRead;
                while ((byteRead = fileInputStream.read(buffer)) != -1) {
                    fileOutputStream.write(buffer, 0, byteRead);
                }
                fileInputStream.close();
                fileOutputStream.flush();
                fileOutputStream.close();
            }
        }catch (Exception e){
            e.printStackTrace();
        }

        t_bpf.flag=0;
        t_log.flag=0;
    }
}
