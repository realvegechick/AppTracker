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
                SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.CHINA);
                Date date = new Date(System.currentTimeMillis());
                String time = simpleDateFormat.format(date);
                String tabname= "`"+pkgName+" "+time+"`";
                Database.createTab(tabname);
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
                            String timeStamp = line.substring(0, space);
                            System.out.println(timeStamp);

                            String serviceName = line.substring(index + 1,
                                    index = line.indexOf(".", index + 1));
                            String methodName = line.substring(index + 1,
                                    index = line.indexOf("(", index + 1));
                            String parameters = line.substring(index + 1,
                                    line.indexOf(")", index + 1));
                            if (parameters.length() == 0)
                                parameters = null;

                            Database.insert(tabname, timeStamp, serviceName, methodName, parameters, callingUid, callingPid);
                            isEmptyTab = false;

                            Log.d("MaldectTest.Log", line);
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
        String filter;
        public void run() {
            try {
                Socket s = new Socket("127.0.0.1",23334);
                InputStream is = s.getInputStream();
                BufferedReader br = new BufferedReader(new InputStreamReader(is));
                String line;
                while ((line = br.readLine()) != null && flag==1) {
                    if (line.contains("AppTracker") && (!line.contains("MaldectTest"))) {
                        //Todo: SQLite
                        Log.d("MaldectTest.BPF",line);
                    }
                }
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
        //t_bpf=new BPFThread();
        //t_bpf.flag=1;
        //t_bpf.start();
    }
    static void stopTrack() {
        t_bpf.flag=0;
        t_log.flag=0;
    }
}
