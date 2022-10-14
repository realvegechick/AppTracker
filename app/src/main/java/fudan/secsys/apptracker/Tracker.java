package fudan.secsys.apptracker;

import android.location.Location;
import android.util.Log;
import android.widget.Toast;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.Socket;
import fudan.secsys.apptracker.Database;

public class Tracker {
    static class LogThread extends Thread {
        int flag = 1;
        public void run() {
            try {
                Process process = Runtime.getRuntime().exec("logcat");
                InputStream is = process.getInputStream();
                BufferedReader br = new BufferedReader(new InputStreamReader(is));
                String line;
                while ((line = br.readLine()) != null && flag==1) {
                    //if (line.contains("AppTracker") && (!line.contains("MaldectTest"))) {
                    if(line.contains("Maldetect")){
                        //Todo: SQLite
                        int index;
                        int callingUid = Integer.parseInt(line.substring(line.indexOf("callingUid:") + "callingUid:".length(),
                                index = line.indexOf(",")));
                        int callingPid = Integer.parseInt(line.substring(line.indexOf("callingPid:") + "callingPid:".length(),
                                index = line.indexOf(",", index + 1)));
                        String serviceName = line.substring(index + 1,
                                index = line.indexOf(".", index + 1));
                        String methodName = line.substring(index + 1,
                                index = line.indexOf("(", index + 1));
                        String parameters = line.substring(index + 1,
                                index = line.indexOf(")", index + 1));
                        if(parameters.length() == 0)
                            parameters=null;

                        Database.insert(serviceName, methodName, parameters, callingUid, callingPid);

                        Log.d("MaldectTest.Log", line);
                    }
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
        t_log=new LogThread();
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
