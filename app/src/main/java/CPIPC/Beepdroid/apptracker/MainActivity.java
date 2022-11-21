package CPIPC.Beepdroid.apptracker;

import androidx.appcompat.app.AppCompatActivity;


import android.content.Intent;
import android.content.pm.PackageManager;
import android.content.pm.ResolveInfo;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Toast;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;

public class MainActivity extends AppCompatActivity {
    static List<String> APP;

    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        final EditText text=findViewById(R.id.app_name);
        final Button button_start=findViewById(R.id.start);
        final Button button_stop=findViewById(R.id.stop);
        button_start.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                getAppProcessName();
                String name=text.getText().toString();
                int appUid=0;
                if(APP.indexOf(name)!=-1) {
                    try {
                        Process process = Runtime.getRuntime().exec("cmd package list packages -U");
                        InputStream is = process.getInputStream();
                        BufferedReader br = new BufferedReader(new InputStreamReader(is));
                        String line;
                        while ((line = br.readLine()) != null){
                            if(line.contains(name)){
                                appUid = Integer.parseInt(line.substring(line.indexOf("uid:") + "uid:".length()));
                                break;
                            }
                        }
                    } catch (IOException e) {
                        e.printStackTrace();
                    }

                    text.setEnabled(false);
                    button_start.setEnabled(false);
                    button_stop.setEnabled(true);
                    Tracker.startTrack(name, appUid);
                }
                else{
                    Toast.makeText(getApplicationContext(),"No such APP!",Toast.LENGTH_SHORT).show();
                }
            }
        });
        button_stop.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                text.setEnabled(true);
                button_start.setEnabled(true);
                button_stop.setEnabled(false);
                Tracker.stopTrack(v.getContext());
            }
        });
    }


    public void getAppProcessName() {
        APP=new ArrayList<>();
        //当前应用pid
        final PackageManager packageManager = getApplicationContext().getPackageManager();
        final Intent mainIntent = new Intent(Intent.ACTION_MAIN, null);
        mainIntent.addCategory(Intent.CATEGORY_LAUNCHER);
        // get all apps
        final List<ResolveInfo> apps = packageManager.queryIntentActivities(mainIntent, 0);
        for (int i = 0; i < apps.size(); i++) {
            String name = apps.get(i).activityInfo.packageName;
            if (!name.contains("huawei") && !name.contains("android")) {
                APP.add(apps.get(i).activityInfo.packageName);
            }
        }
    }

}
