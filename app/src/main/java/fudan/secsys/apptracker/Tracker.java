package fudan.secsys.apptracker;

import android.accessibilityservice.AccessibilityService;
import android.app.Activity;
import android.app.ActivityManager;
import android.content.Context;
import android.location.Location;
import android.util.Log;
import android.view.View;
import android.widget.Toast;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.lang.reflect.Array;
import java.net.ServerSocket;
import java.net.Socket;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import java.util.Locale;

import fudan.secsys.apptracker.Database;

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
                //SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.CHINA);
                Date date = new Date(System.currentTimeMillis());
                //String time = String.valueOf(System.currentTimeMillis());
                String tabname= "`"+pkgName+" "+date+" Log`";
                Database.createLog(tabname);
                boolean isEmptyTab = true;

                while ((line = br.readLine()) != null && flag==1) {
                    if(line.contains("Maldetect")) {
                        int index;
                        int callingUid = Integer.parseInt(line.substring(line.indexOf("callingUid:") + "callingUid:".length(),
                                index = line.indexOf(",")));
                        int callingPid = Integer.parseInt(line.substring(line.indexOf("callingPid:") + "callingPid:".length(),
                                index = line.indexOf(",", index + 1)));

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
                            String parameters = line.substring(index + 1,
                                    line.indexOf(")", index + 1));
                            if (parameters.length() == 0)
                                parameters = null;
                            long finalTimeStamp = timeStamp;
                            String finalParameters = parameters;
                            Thread t=new Thread(() -> {
                                try {
                                    Database.insertLog(tabname, finalTimeStamp, serviceName, methodName, finalParameters, callingPid);
                                } catch (Exception e) {
                                    e.printStackTrace();
                                }
                            });
                            t.start();
                            isEmptyTab = false;

                        }
                    }
                }
                //删除空表
                if(isEmptyTab){
                    Database.dropTab(tabname);
                }
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
                Database.createBPF(tabname);
                boolean isEmptyTab = true;

                while ((line = br.readLine()) != null && flag==1) {
                    if(line.contains(pkgName)) {
                        String[] str_array=line.split(", ");
                        final String syscall,str;
                        final long time,pid,ret;
                        long args[]=new long[6];
                        if(str_array.length>5){//sys_enter
                            time=Long.parseLong(str_array[0]);
                            pid=Long.parseLong(str_array[2]);
                            syscall=str_array[3];
                            args[0]=Long.parseLong(str_array[4]);
                            args[1]=Long.parseLong(str_array[5]);
                            args[2]=Long.parseLong(str_array[6]);
                            args[3]=Long.parseLong(str_array[7]);
                            args[4]=Long.parseLong(str_array[8]);
                            args[5]=Long.parseLong(str_array[9]);
                            if(str_array.length>10)
                                str=str_array[10];
                            else
                                str=null;
                            //line="time:"+time+", app:"+app+", pid:"+pid+", syscall:"+syscall+", arg0:"+arg0+", arg1:"+arg1+", arg2:"+arg2+", arg3:"+arg3+", arg4:"+arg4+", arg5:"+arg5+", str:"+str;
                            //Log.d("MaldectTest.BPF",line);
                            Thread t=new Thread(() -> {
                                try {
                                    Database.insertBPF(tabname, time, pid, syscall, args.toString(), str, -2147483648, false);
                                } catch (Exception e) {
                                    e.printStackTrace();
                                }
                            });
                            t.start();
                            isEmptyTab = false;
                        }
                        else{//sys_exit
                            time=Long.parseLong(str_array[0]);
                            pid=Long.parseLong(str_array[2]);
                            syscall=str_array[3];
                            ret=Long.parseLong(str_array[4]);
                            //line="time:"+time+", app:"+app+", pid:"+pid+", syscall:"+syscall+", ret:"+ret;
                            //Log.d("MaldectTest.BPF",line);
                            Thread t=new Thread(() -> {
                                try {
                                    Database.insertBPF(tabname, time, pid, syscall, null, null, ret, true);
                                } catch (Exception e) {
                                    e.printStackTrace();
                                }
                            });
                            t.start();
                            isEmptyTab = false;

                        }

                    }
                }
                //删除空表
                if(isEmptyTab){
                    Database.dropTab(tabname);
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }
    static LogThread t_log;
    static BPFThread t_bpf;
    static void startTrack(String app_name){
        /*t_log=new LogThread(app_name);
        t_log.flag=1;
        t_log.start();*/
        t_bpf=new BPFThread(app_name);
        t_bpf.flag=1;
        t_bpf.start();
    }
    static void stopTrack() {
        t_bpf.flag=0;
        //t_log.flag=0;
    }
}
