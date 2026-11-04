package app.raiun.test.r8recovery;

import android.app.Activity;
import android.app.Instrumentation;
import android.content.ContentValues;
import android.content.Context;
import android.content.SharedPreferences;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.os.Bundle;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Collections;
import java.util.UUID;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

/** Framework-only fixture: all application/library implementations come from target DEX. */
public final class R8RecoveryInstrumentation extends Instrumentation {
    private static final String[][] SYMBOLS = __SYMBOLS__;
    private static final boolean MAPPED = __MAPPED__;
    private static final String PREFIX = "r8-recovery-synthetic-";
    private static final String ACCOUNT = PREFIX + "account";
    private static final String PASSWORD = "public-synthetic-fixture-password";
    private static final byte[] SENTINEL = "public synthetic private offline bytes".getBytes(java.nio.charset.StandardCharsets.UTF_8);
    private static final String[] RUNNABLE = {"QUEUED", "RETRY", "RUNNING"};
    private static final String[] RETAINED = {"SUCCEEDED", "CANCELLED", "AWAITING_UNLOCK", "CONFLICT", "FUTURE_UNKNOWN"};
    private String phase;
    private String stage = "entry";
    private static final class Unsupported extends Exception {}

    @Override public void onCreate(Bundle arguments) {
        super.onCreate(arguments);
        phase = arguments == null ? "invalid" : arguments.getString("phase", "invalid");
        start();
    }
    @Override public void onStart() {
        Bundle result = new Bundle();
        result.putString("phase", phase);
        try {
            check("app.raiun.cloud".equals(getTargetContext().getPackageName()));
            if ("seed".equals(phase)) seed();
            else if ("verify".equals(phase)) verify();
            else throw new IllegalArgumentException();
            result.putString("status", "pass");
            result.putString("stage", stage);
            result.putInt("pid", android.os.Process.myPid());
            result.putInt("version_code", getTargetContext().getPackageManager().getPackageInfo("app.raiun.cloud", 0).versionCode);
            if ("seed".equals(phase)) {
                result.putString("baseline_cleanup_work", "ENQUEUED");
                result.putString("baseline_transfer_workers", "absent");
                result.putString("baseline_runnable_intents", "3-future-not-before");
            } else {
                result.putString("recovered_runnable_intents", "3-local-UNSUPPORTED-no-network");
                result.putString("retained_nonrunnable_intents", "5-no-replay");
                result.putString("persisted_cleanup_worker", "SUCCEEDED");
            }
            finish(Activity.RESULT_OK, result);
        } catch (Unsupported unavailable) {
            result.putString("status", "unsupported-optimized-shape");
            result.putString("stage", stage);
            finish(Activity.RESULT_CANCELED, result);
        } catch (Throwable error) {
            result.putString("status", "fail");
            result.putString("stage", stage);
            for (int n = 0; error != null && n < 4; n++, error = error.getCause()) {
                result.putString("exception_type_" + n, error.getClass().getName());
            }
            finish(Activity.RESULT_CANCELED, result);
        }
    }
    private static void check(boolean value) { if (!value) throw new AssertionError(); }
    private String symbol(String key, String fallback) throws Unsupported {
        if (!MAPPED) return fallback;
        for (String[] pair : SYMBOLS) if (pair[0].equals(key)) return pair[1];
        throw new Unsupported();
    }
    private Class<?> type(String original) throws Exception {
        try { return Class.forName(symbol(original, original), true, getTargetContext().getClassLoader()); }
        catch (ClassNotFoundException e) { throw new Unsupported(); }
    }
    private Method method(String owner, String name, Class<?>... params) throws Exception {
        Class<?> holder = type(owner);
        String mappedName = symbol(owner + "#" + name, name);
        // A merged method has a different residual holder. Metadata never changes the app.
        if (MAPPED) holder = Class.forName(symbol(owner + "#" + name + "@holder", holder.getName()), true, getTargetContext().getClassLoader());
        try { Method m = holder.getDeclaredMethod(mappedName, params); m.setAccessible(true); return m; }
        catch (NoSuchMethodException e) { throw new Unsupported(); }
    }
    private Object credentials() throws Exception {
        String original = "eu.opencloud.android.next.core.security.KeystoreCredentialStore";
        String holder = symbol(original + "#<init>@holder", original);
        try {
            Constructor<?> ctor = Class.forName(holder, true, getTargetContext().getClassLoader()).getDeclaredConstructor(Context.class);
            ctor.setAccessible(true);
            return ctor.newInstance(getTargetContext());
        } catch (NoSuchMethodException | ClassNotFoundException unavailable) { throw new Unsupported(); }
    }
    private SQLiteDatabase database() throws Exception {
        File file = getTargetContext().getDatabasePath("opencloud-file-browser.db");
        for (int i = 0; !file.isFile() && i < 100; i++) Thread.sleep(50);
        check(file.isFile());
        SQLiteDatabase db = SQLiteDatabase.openDatabase(file.toString(), null, SQLiteDatabase.OPEN_READWRITE);
        check(db.getVersion() == 28);
        check("b1be411beeaa67920442712a366d4885".equals(string(db, "SELECT identity_hash FROM room_master_table WHERE id=42")));
        return db;
    }
    private static String string(SQLiteDatabase db, String sql, String... args) {
        try (Cursor c = db.rawQuery(sql, args)) { return c.moveToFirst() ? c.getString(0) : null; }
    }
    private static void insert(SQLiteDatabase db, String table, ContentValues values) {
        // Populate every real NOT NULL column; explicit fixture values override neutral defaults.
        try (Cursor c = db.rawQuery("PRAGMA table_info(`" + table + "`)", null)) {
            while(c.moveToNext()) if (c.getInt(3) != 0 && !values.containsKey(c.getString(1)) && c.isNull(4)
                    && !(c.getInt(5) != 0 && "INTEGER".equals(c.getString(2)))) {
                if ("INTEGER".equals(c.getString(2))) values.put(c.getString(1), 0);
                else values.put(c.getString(1), "");
            }
        }
        check(db.insertOrThrow(table, null, values) != -1);
    }
    private File offline() { return new File(getTargetContext().getFilesDir(), "resources/" + PREFIX + "pinned.bin"); }
    private File orphan() { return new File(getTargetContext().getFilesDir(), "resources/" + PREFIX + "orphan.bin"); }
    private File settings() { return new File(getTargetContext().getFilesDir(), "datastore/opencloud-settings.pb"); }
    private SharedPreferences marker() { return getTargetContext().getSharedPreferences("r8_recovery_fixture", 0); }
    private static void write(File file, byte[] bytes) throws Exception {
        check(file.getParentFile().isDirectory() || file.getParentFile().mkdirs());
        try (FileOutputStream out = new FileOutputStream(file)) { out.write(bytes); out.getFD().sync(); }
    }
    private static byte[] read(File file) throws Exception {
        try (FileInputStream in = new FileInputStream(file); java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream()) {
            byte[] chunk = new byte[4096]; int n;
            while ((n = in.read(chunk)) != -1) out.write(chunk, 0, n);
            return out.toByteArray();
        }
    }
    private static String hash(byte[] bytes) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(bytes);
        StringBuilder text = new StringBuilder(); for (byte b : digest) text.append(String.format(java.util.Locale.ROOT, "%02x", b & 255));
        return text.toString();
    }
    private static String workId(String state) { return UUID.nameUUIDFromBytes((PREFIX + state).getBytes(java.nio.charset.StandardCharsets.UTF_8)).toString(); }
    private void seed() throws Exception {
        check(!MAPPED);
        stage = "baseline-version-and-isolation";
        check(getTargetContext().getPackageManager().getPackageInfo("app.raiun.cloud", 0).versionCode == 53);
        check(!marker().contains("seeded"));
        Thread.sleep(3000); // Initial startup recovery finishes before admitting synthetic durable intents.
        try (SQLiteDatabase db = database()) {
            check("0".equals(string(db, "SELECT COUNT(*) FROM accounts")));
            stage = "seed-account-resource";
            ContentValues account = new ContentValues();
            account.put("id", ACCOUNT); account.put("serverUrl", "https://127.0.0.1:1"); account.put("userId", PREFIX + "user");
            account.put("displayName", "Synthetic R8 fixture"); account.put("authenticationType", "BASIC"); account.put("isActive", 1);
            insert(db, "accounts", account);
            write(offline(), SENTINEL); write(orphan(), SENTINEL);
            ContentValues resource = new ContentValues(); resource.put("accountId", ACCOUNT); resource.put("spaceId", PREFIX + "space");
            resource.put("remoteId", PREFIX + "file"); resource.put("name", "synthetic.bin"); resource.put("path", "/synthetic.bin");
            resource.put("kind", "FILE"); resource.put("sizeBytes", SENTINEL.length); resource.put("hasLocalCopy", 1);
            resource.put("offlinePinned", 1); resource.put("localPath", offline().getAbsolutePath()); insert(db, "resources", resource);
            ContentValues excluded = new ContentValues(); excluded.put("path", orphan().getAbsolutePath()); insert(db, "excluded_cache", excluded);
            stage = "seed-real-keystore-credentials";
            Object creds = credentials();
            method("eu.opencloud.android.next.core.security.KeystoreCredentialStore", "saveBasicCredentials", String.class, String.class, String.class)
                .invoke(creds, ACCOUNT, "synthetic-user", PASSWORD);
            check(PASSWORD.equals(method("eu.opencloud.android.next.core.security.KeystoreCredentialStore", "readBasicPassword", String.class).invoke(creds, ACCOUNT)));
            SharedPreferences saved = getTargetContext().getSharedPreferences("secure_credentials", 0);
            String encrypted = saved.getString("basic." + ACCOUNT, ""); check(encrypted.startsWith("v2:")); check(!encrypted.contains(PASSWORD));
            stage = "seed-settings";
            // Valid proto3: layout=TILES, retention=14, dark appearance, temp retention=24, hide size.
            byte[] wire = new byte[] {8,3,24,14,40,2,48,24,56,1}; write(settings(), wire);
            check(marker().edit().putBoolean("seeded", true).putInt("pid", android.os.Process.myPid())
                .putString("credential_hash", hash(encrypted.getBytes(java.nio.charset.StandardCharsets.UTF_8)))
                .putString("settings_hash", hash(wire)).commit());
            stage = "seed-durable-transfer-intents";
            long after = System.currentTimeMillis() + 90000;
            db.beginTransaction();
            try {
                for (String state : RUNNABLE) transfer(db, state, after);
                for (String state : RETAINED) transfer(db, state, after);
                db.setTransactionSuccessful();
            } finally { db.endTransaction(); }
            stage = "enqueue-real-delayed-cleanup-worker";
            enqueueCleanup();
            check("8".equals(string(db, "SELECT COUNT(*) FROM transfers WHERE accountId=?", ACCOUNT)));
            check("3".equals(string(db, "SELECT COUNT(*) FROM transfers WHERE accountId=? AND state IN ('QUEUED','RUNNING','RETRY') AND notBeforeEpochMillis>?", ACCOUNT, Long.toString(System.currentTimeMillis()))));
            try (SQLiteDatabase work = SQLiteDatabase.openDatabase(new File(getTargetContext().getNoBackupFilesDir(), "androidx.work.workdb").toString(), null, SQLiteDatabase.OPEN_READONLY)) {
                check("0".equals(string(work, "SELECT state FROM WorkSpec WHERE id=?", marker().getString("cleanup_work", ""))));
                for (String state : RUNNABLE) check(string(work, "SELECT state FROM WorkSpec WHERE id=?", workId(state)) == null);
            }
            check(orphan().isFile()); check(Arrays.equals(SENTINEL, read(offline())));
        }
        stage = "baseline-seeded-await-upgrade";
    }
    private void transfer(SQLiteDatabase db, String state, long after) {
        ContentValues row = new ContentValues(); row.put("id", PREFIX + state); row.put("accountId", ACCOUNT);
        row.put("spaceId", PREFIX + "space"); row.put("direction", "RETRY".equals(state) ? "UPLOAD" : "DOWNLOAD");
        row.put("destinationPath", "/synthetic-" + state); row.put("displayName", "Synthetic fixture"); row.put("bytesTotal", 64);
        row.put("bytesTransferred", 7); row.put("state", state); row.put("workId", workId(state)); row.put("locationKind", "SYNTHETIC_UNSUPPORTED");
        row.put("attemptCount", 2); row.put("notBeforeEpochMillis", after); row.put("createdAtEpochMillis", 12345);
        row.put("updatedAtEpochMillis", 12345); row.put("expectedETag", "synthetic-etag"); insert(db, "transfers", row);
        if (Arrays.asList(RUNNABLE).contains(state)) {
            ContentValues queue = new ContentValues(); queue.put("transferId", PREFIX + state); insert(db, "transfer_queue", queue);
        }
    }
    private void enqueueCleanup() throws Exception {
        ClassLoader loader = getTargetContext().getClassLoader();
        Class<?> builderType = Class.forName("androidx.work.OneTimeWorkRequest$Builder", true, loader);
        Object builder = builderType.getConstructor(Class.class).newInstance(Class.forName("eu.opencloud.android.next.core.sync.ExcludedCacheCleanupWorker", true, loader));
        builderType.getMethod("setInitialDelay", long.class, TimeUnit.class).invoke(builder, 90L, TimeUnit.SECONDS);
        Object request = builderType.getMethod("build").invoke(builder);
        UUID id = (UUID) request.getClass().getMethod("getId").invoke(request);
        Class<?> wmType = Class.forName("androidx.work.WorkManager", true, loader);
        Object wm = wmType.getMethod("getInstance", Context.class).invoke(null, getTargetContext());
        Object operation = wmType.getMethod("enqueue", java.util.List.class).invoke(wm, Collections.singletonList(request));
        Method result = operation.getClass().getMethod("getResult"); result.setAccessible(true);
        ((Future<?>) result.invoke(operation)).get(15, TimeUnit.SECONDS);
        check(marker().edit().putString("cleanup_work", id.toString()).commit());
    }
    private void verify() throws Exception {
        stage = "higher-code-cold-process";
        check(marker().getBoolean("seeded", false));
        check(marker().getInt("pid", -1) != android.os.Process.myPid());
        check(getTargetContext().getPackageManager().getPackageInfo("app.raiun.cloud", 0).versionCode > 53);
        stage = "real-room-reopen";
        Class<?> room = type("eu.opencloud.android.next.core.database.FileBrowserDatabase");
        Field instance = room.getDeclaredField(symbol("eu.opencloud.android.next.core.database.FileBrowserDatabase#instance", "instance")); instance.setAccessible(true);
        Object opened = null; for (int n=0; n < 200 && opened == null; n++) { opened = instance.get(null); if (opened == null) Thread.sleep(50); }
        check(opened != null);
        Object helper = method("androidx.room.RoomDatabase", "getOpenHelper").invoke(opened);
        Object writable = method("androidx.sqlite.db.SupportSQLiteOpenHelper", "getWritableDatabase").invoke(helper);
        check(writable != null);
        stage = "real-credential-decrypt-after-upgrade";
        Object creds = credentials();
        check(PASSWORD.equals(method("eu.opencloud.android.next.core.security.KeystoreCredentialStore", "readBasicPassword", String.class).invoke(creds, ACCOUNT)));
        String encrypted = getTargetContext().getSharedPreferences("secure_credentials", 0).getString("basic." + ACCOUNT, "");
        check(marker().getString("credential_hash", "").equals(hash(encrypted.getBytes(java.nio.charset.StandardCharsets.UTF_8))));
        stage = "settings-offline-preservation";
        check(marker().getString("settings_hash", "").equals(hash(read(settings())))); check(Arrays.equals(SENTINEL, read(offline())));
        try (SQLiteDatabase db = database()) {
            check("1".equals(string(db, "SELECT COUNT(*) FROM accounts WHERE id=? AND isActive=1 AND removalPending=0", ACCOUNT)));
            check("1".equals(string(db, "SELECT COUNT(*) FROM resources WHERE accountId=? AND offlinePinned=1 AND hasLocalCopy=1 AND localPath=?", ACCOUNT, offline().getAbsolutePath())));
            stage = "await-real-transfer-and-worker-recovery";
            long deadline = System.currentTimeMillis() + 180000;
            while (System.currentTimeMillis() < deadline) {
                if ("3".equals(string(db, "SELECT COUNT(*) FROM transfers WHERE accountId=? AND state='FAILED' AND errorCode='UNSUPPORTED'", ACCOUNT))
                        && !orphan().exists() && cleanupSucceeded()) break;
                Thread.sleep(250);
            }
            for (String state : RUNNABLE) {
                check("1".equals(string(db, "SELECT COUNT(*) FROM transfers WHERE id=? AND state='FAILED' AND errorCode='UNSUPPORTED' AND workId=? AND bytesTransferred=7 AND attemptCount=2 AND expectedETag='synthetic-etag'", PREFIX + state, workId(state))));
            }
            stage = "terminal-unlock-conflict-no-replay";
            for (String state : RETAINED) {
                check("1".equals(string(db, "SELECT COUNT(*) FROM transfers WHERE id=? AND state=? AND workId=? AND bytesTransferred=7 AND attemptCount=2 AND updatedAtEpochMillis=12345", PREFIX + state, state, workId(state))));
            }
            check(!orphan().exists()); check(Arrays.equals(SENTINEL, read(offline())));
            check("0".equals(string(db, "SELECT COUNT(*) FROM excluded_cache WHERE path=?", orphan().getAbsolutePath())));
        }
        stage = "real-persisted-workspec-results";
        File workFile = new File(getTargetContext().getNoBackupFilesDir(), "androidx.work.workdb");
        check(workFile.isFile());
        try (SQLiteDatabase work = SQLiteDatabase.openDatabase(workFile.toString(), null, SQLiteDatabase.OPEN_READONLY)) {
            for (String state : RUNNABLE) check("3".equals(string(work, "SELECT state FROM WorkSpec WHERE id=?", workId(state))));
            for (String state : RETAINED) check(string(work, "SELECT state FROM WorkSpec WHERE id=?", workId(state)) == null);
            String cleanup = marker().getString("cleanup_work", "");
            check("2".equals(string(work, "SELECT state FROM WorkSpec WHERE id=? AND worker_class_name='eu.opencloud.android.next.core.sync.ExcludedCacheCleanupWorker'", cleanup)));
        }
        stage = "upgrade-preserved-and-cold-recovery-complete";
    }
    private boolean cleanupSucceeded() {
        File file = new File(getTargetContext().getNoBackupFilesDir(), "androidx.work.workdb");
        if (!file.isFile()) return false;
        try (SQLiteDatabase work = SQLiteDatabase.openDatabase(file.toString(), null, SQLiteDatabase.OPEN_READONLY)) {
            return "2".equals(string(work, "SELECT state FROM WorkSpec WHERE id=?", marker().getString("cleanup_work", "")));
        }
    }
}
