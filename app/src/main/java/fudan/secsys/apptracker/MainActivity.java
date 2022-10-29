package fudan.secsys.apptracker;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.appcompat.app.AppCompatActivity;


import android.content.Context;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.content.pm.ResolveInfo;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.ListIterator;

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
                if(APP.indexOf(name)!=-1) {
                    text.setEnabled(false);
                    button_start.setEnabled(false);
                    button_stop.setEnabled(true);
                    Tracker.startTrack(name);
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
