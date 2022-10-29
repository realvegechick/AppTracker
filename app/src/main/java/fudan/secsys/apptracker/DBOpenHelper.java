package fudan.secsys.apptracker;

import android.content.Context;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteOpenHelper;

import androidx.annotation.Nullable;

public class DBOpenHelper extends SQLiteOpenHelper {
    public DBOpenHelper(@Nullable Context context, @Nullable String name, @Nullable SQLiteDatabase.CursorFactory factory, int version) {
        super(context, name, factory, version);
    }

    @Override
    public void onCreate(SQLiteDatabase sqLiteDatabase) {
        String createTabSql = "CREATE TABLE Log" + "(tag varchar(50), timeStamp long, callingPid long, serviceName varchar(50), methodName varchar(50), parameters varchar(1024))";
        sqLiteDatabase.execSQL(createTabSql);
        createTabSql = "CREATE TABLE BPF" + "(tag varchar(50), timeStamp long, callingPid long, syscall varchar(30), parameters varchar(200), str varchar(256), ret long)";
        sqLiteDatabase.execSQL(createTabSql);

    }

    @Override
    public void onUpgrade(SQLiteDatabase sqLiteDatabase, int i, int i1) {

    }
}
