package fudan.secsys.apptracker;

import android.app.ActivityManager;
import android.app.AlertDialog;
import android.content.Context;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteStatement;
import android.os.Handler;
import android.os.Message;
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
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.Date;
import java.util.List;
import java.util.Locale;

public class Tracker {
    static class LogThread extends Thread {
        int flag = 1;
        static private String pkgName;
        static private String tabName;

        public LogThread(String app_name, String tabname) {
            pkgName = app_name;
            tabName = tabname;
        }

        public void run() {
            try {
                Process process = Runtime.getRuntime().exec("logcat");
                InputStream is = process.getInputStream();
                BufferedReader br = new BufferedReader(new InputStreamReader(is));
                String line;
        //        DBOpenHelper dbOpenHelper = new DBOpenHelper(MyApplication.getContext(), "test9.db", null, 1);
        //        SQLiteDatabase db = dbOpenHelper.getWritableDatabase();

                try {
                    //db.execSQL("PRAGMA synchronous = OFF;");
                    //db.execSQL("begin;");
                    db.beginTransaction();

                    String sql = "insert into Log(tag, timeStamp, callingPid, serviceName, methodName, parameters) values(?,?,?,?,?,?);";
                    SQLiteStatement statement = db.compileStatement(sql);

                    while ((line = br.readLine()) != null && flag == 1) {
                        if (line.contains("Maldetect") && line.contains("callingUid:") && line.contains("callingPid:")) {
                            int index = 0;
                            int callingUid = Integer.parseInt(line.substring(line.indexOf("callingUid:") + "callingUid:".length(),
                                    index = line.indexOf(",")));
                            long callingPid = Long.parseLong(line.substring(line.indexOf("callingPid:") + "callingPid:".length(),
                                    index = line.indexOf(",", index + 1)));

                            //匹配输入的包名
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
                            if (callingPkgName.contains(pkgName)) {
                                //Todo: SQLite
                                int space = line.indexOf(" ");
                                space = line.indexOf(" ", space + 1);
                                String formatTime = "2022-" + line.substring(0, space);
                                SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyy-MM-dd hh:mm:ss.SSS", Locale.CHINA);
                                long timeStamp = 0;
                                try {
                                    Date date = simpleDateFormat.parse(formatTime);
                                    timeStamp = date.getTime();
                                } catch (Exception e) {
                                    e.printStackTrace();
                                }

                                String serviceName = line.substring(index + 1,
                                        index = line.indexOf(".", index + 1));
                                String methodName = line.substring(index + 1,
                                        index = line.indexOf("(", index + 1));
                                String parameters = null;
                                if (line.indexOf(")", index + 1) - (index + 1) > 1) {
                                    parameters = line.substring(index + 1,
                                            line.indexOf(")", index + 1));
                                }

                                long finalTimeStamp = timeStamp;
                                String finalParameters = parameters;

                                statement.bindString(1, tabName);
                                statement.bindLong(2, finalTimeStamp);
                                statement.bindLong(3, callingPid);
                                statement.bindString(4, serviceName);
                                statement.bindString(5, methodName);
                                if (finalParameters != null)
                                    statement.bindString(6, finalParameters);
                                else
                                    statement.bindString(6, "");
                                statement.executeInsert();

                            }
                        }
                    }
                    //db.execSQL("commit;");
                    db.setTransactionSuccessful();
                } catch (Exception e){
                    e.printStackTrace();
                } finally {
                    db.endTransaction();
                //    db.close();
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }
    static class BPFThread extends Thread {
        int flag = 1;
        static private String pkgName;
        static private String tabName;
        public Handler mHandler=null;

        //获取另一个线程的Handler
        public void setHandler( Handler handler){
            mHandler = handler;
        }

        public BPFThread(String app_name, String tabname) {
            pkgName = app_name;
            tabName = tabname;
        }
        public void run() {
            try {
                ServerSocket s = new ServerSocket(23334);
                Socket server = s.accept();
                InputStream is = server.getInputStream();
                BufferedReader br = new BufferedReader(new InputStreamReader(is));
                String line;

                int enter = 0, exit = 0;
                List<BPFinfo> list = new ArrayList<BPFinfo>();
                while ((line = br.readLine()) != null && flag == 1) {
                    if (line.contains(pkgName)) {
                        String[] str_array = line.split(", ");
                        final String syscall, str;
                        final long time, pid, ret;
                        long args[] = new long[6];
                        if (str_array.length > 5) {//sys_enter
                            enter += 1;
                            time = Long.parseLong(str_array[0]);
                            pid = Long.parseLong(str_array[2]);
                            syscall = str_array[3];
                            args[0] = Long.parseUnsignedLong(str_array[4]);
                            args[1] = Long.parseUnsignedLong(str_array[5]);
                            args[2] = Long.parseUnsignedLong(str_array[6]);
                            args[3] = Long.parseUnsignedLong(str_array[7]);
                            args[4] = Long.parseUnsignedLong(str_array[8]);
                            args[5] = Long.parseUnsignedLong(str_array[9]);
                            if (str_array.length > 10)
                                str = str_array[10];
                            else
                                str = null;

                            list.add(new BPFinfo(time, pid, syscall, args[0] + "," + args[1] + "," + args[2] + "," + args[3] + "," + args[4] + "," + args[5], str, -2147483648));
                        } else {//sys_exit
                            exit += 1;
                            time = Long.parseLong(str_array[0]);
                            pid = Long.parseLong(str_array[2]);
                            syscall = str_array[3];
                            ret = Long.parseLong(str_array[4]);

                            list.add(new BPFinfo(time, pid, syscall, "", "", ret));
                        }
                    }
                }
                Log.d("maldebug", "enter: " + enter + " exit: " + exit);

                //merge
                //enterBPF = enterBPF.stream().sorted(Comparator.comparing(BPFinfo::BPFtime).reversed()).collect(Collectors.toList());
                Collections.sort(list, (bpFinfo, t1) -> {
                    if (bpFinfo == null && t1 == null)
                        return 0;
                    if (bpFinfo == null)
                        return 1;
                    if (t1 == null)
                        return -1;
                    //return (int) (t1.BPFtime - bpFinfo.BPFtime);
                    return Long.compare(t1.BPFtime, bpFinfo.BPFtime);
                });
                Log.d("maldebug", "Total bpf:"+list.size());

                for (int i = 0; i < list.size(); i++) {
                    BPFinfo term = list.get(i);
                    long timeinfo = term.BPFtime;
                    long pidinfo = term.BPFpid;
                    String sysinfo = term.BPFsys;
                    //String arginfo = term.BPFarg;
                    //String strinfo = term.BPFstr;
                    long retinfo = term.BPFret;
                    if (retinfo != -2147483648) {//exit
                        int i_enter = i + 1;
                        for (; i_enter < list.size(); i_enter++) {
                            BPFinfo find = list.get(i_enter);
                            long findtime = find.BPFtime;
                            long findpid = find.BPFpid;
                            String findsys = find.BPFsys;
                            String findarg = find.BPFarg;
                            String findstr = find.BPFstr;
                            //long findret = find.BPFret;
                            if (findpid != pidinfo || !findsys.equals(sysinfo) || findtime >= timeinfo)
                                continue;
                            //found
                            list.set(i, new BPFinfo(findtime, findpid, findsys, findarg, findstr, retinfo));
                            list.remove(i_enter);
                            break;
                        }
                    }
                }
                Log.d("maldebug", "Total bpf after merge: "+list.size());

                try {
                    Thread.sleep(3000);
                } catch (Exception e) {
                    e.printStackTrace();
                }

        //        DBOpenHelper dbOpenHelper = new DBOpenHelper(MyApplication.getContext(), "test9.db", null, 1);
        //        SQLiteDatabase db = dbOpenHelper.getWritableDatabase();
                try{
                    db.execSQL("PRAGMA synchronous = OFF;");
                    //db.execSQL("begin;");
                    db.beginTransaction();

                    String sql = "insert into BPF(tag, timeStamp, callingPid, syscall, parameters, str, ret) values(?,?,?,?,?,?,?);";
                    SQLiteStatement statement = db.compileStatement(sql);
                    for (int i = 0; i < list.size(); i++) {
                        BPFinfo res = list.get(i);
                        statement.bindString(1, tabName);
                        statement.bindLong(2, res.BPFtime);
                        statement.bindLong(3, res.BPFpid);
                        statement.bindString(4, res.BPFsys);
                        if (res.BPFarg != null)
                            statement.bindString(5, res.BPFarg);
                        else
                            statement.bindString(5, "");
                        if (res.BPFstr != null)
                            statement.bindString(6, res.BPFstr);
                        else
                            statement.bindString(6, "");
                        statement.bindLong(7, res.BPFret);
                        statement.executeInsert();
                    }
                    //db.execSQL("commit;");
                    db.setTransactionSuccessful();
                } catch (Exception e){
                    e.printStackTrace();
                } finally {
                    db.endTransaction();
                    //db.close();
                }
                //触发结束事件
                Message msg = mHandler.obtainMessage();
                msg.what = 1;
                mHandler.sendMessage(msg);


            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }
    static LogThread t_log;
    static BPFThread t_bpf;
    static void startTrack(String app_name){
        MyDBOpenHelper=new DBOpenHelper(MyApplication.getContext(), "test12.db", null, 1);
        db = MyDBOpenHelper.getWritableDatabase();
        Date date = new Date(System.currentTimeMillis());
        String tabname= app_name+" "+date;
        t_log=new LogThread(app_name, tabname);
        t_log.flag=1;
        t_log.start();
        t_bpf=new BPFThread(app_name, tabname);
        t_bpf.flag=1;
        t_bpf.setHandler(new MyHandler());
        t_bpf.start();
    }
    static void stopTrack(Context context) {
        MyDialog = new AlertDialog.Builder(context).create();
        MyDialog.setMessage("Waiting");
        MyDialog.show();

        t_log.flag=0;
        t_bpf.flag=0;

    }

    public static class BPFinfo {
        public long BPFtime;
        public long BPFpid;
        public String BPFsys;
        public String BPFarg;
        public String BPFstr;
        public long BPFret;

        public BPFinfo(long time, long pid, String sys, String arg, String str, long ret){
            this.BPFtime = time;
            this.BPFpid = pid;
            this.BPFsys =sys;
            this.BPFarg = arg;
            this.BPFstr = str;
            this.BPFret = ret;

        }
    }

    public static class MyHandler extends Handler{
        @Override
        public void handleMessage(Message msg) {
            if(msg.what == 1){
                //dialog dismiss
                MyDialog.dismiss();
                db.close();
                String oldpath = "/data/data/fudan.secsys.apptracker/databases/test12.db";
                String newpath = "/sdcard/database/test12.db";
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
                Log.d("maldebug", "Apptracker FINISH!");
            }
        }
    }
    public static AlertDialog MyDialog;
    public static DBOpenHelper MyDBOpenHelper;
    public static SQLiteDatabase db;
}
