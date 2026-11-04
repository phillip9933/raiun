#!/usr/bin/env python3
"""Build a framework-only instrumentation probe for an independently minimized test APK.

Only the standard debug key is supported. This helper does not build, change,
install or run the target app, and introduces no R8 retention roots into it.
"""

import argparse
import hashlib
import os
import json
import re
from pathlib import Path
import tempfile
import zipfile

from generate_updater_test_apks import newest, run, sdk_directory

PACKAGE = "app.raiun.test.r8probe"
TARGET_PACKAGE = "app.raiun.cloud"
SOURCE = r'''
package app.raiun.test.r8probe;

import android.app.Activity;
import android.app.Instrumentation;
import android.os.Bundle;
import android.graphics.Bitmap;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Paint;
import android.graphics.BitmapFactory;
import android.graphics.pdf.PdfRenderer;
import android.os.ParcelFileDescriptor;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CancellationException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.security.MessageDigest;

/** Uses only framework classes; target types are deliberately absent from this APK. */
public final class R8ProbeInstrumentation extends Instrumentation {
    private String probe;
    private static String stage = "entry";
    // Generated only into this independent APK. Never supplied to the target shrinker.
    private static final String[][] SYMBOLS = __MAPPED_SYMBOLS__;
    private static final boolean MAPPED = __HAS_MAPPING__;
    // Exact APK-bound disassembly recipe; never guessed from constructor arity.
    private static final String[] SCANNER_SHAPE = __SCANNER_SHAPE__;
    private static final class ProbeUnsupported extends Exception { }


    @Override public void onCreate(Bundle arguments) {
        super.onCreate(arguments);
        probe = arguments == null ? "jna" : arguments.getString("probe", "jna");
        start();
    }

    @Override public void onStart() {
        Bundle results = new Bundle();
        if (!"jna".equals(probe) && !"opencv-exception".equals(probe)
                && !"crypto-known-answer".equals(probe) && !"scanner-standard".equals(probe)
                && !"scanner-learned".equals(probe) && !"scanner-export".equals(probe)
                && !"protobuf-roundtrip".equals(probe)) {
            results.putString("status", "invalid-argument");
            results.putString("probe", "invalid");
            finish(Activity.RESULT_CANCELED, results);
            return;
        }
        results.putString("probe", probe);
        try {
            if (!"app.raiun.cloud".equals(getTargetContext().getPackageName())) {
                results.putString("status", "wrong-target");
                finish(Activity.RESULT_CANCELED, results);
                return;
            }
            ClassLoader loader = getTargetContext().getClassLoader();
            if ("jna".equals(probe)) {
                // Initialization, not just class presence: invokes the packaged JNI initIDs path.
                Class.forName("com.sun.jna.Native", true, loader);
            } else if ("crypto-known-answer".equals(probe)) {
                cryptoKnownAnswer(loader);
            } else if ("protobuf-roundtrip".equals(probe)) {
                protobufRoundtrip(loader);
            } else if ("scanner-export".equals(probe)) {
                scannerExport(loader);
            } else if ("scanner-standard".equals(probe) || "scanner-learned".equals(probe)) {
                scanner(loader, "scanner-learned".equals(probe));
            } else {
                // Exact string looked up by OpenCV JNI; no mapped-method or renamed-class guess.
                Class<?> exception = Class.forName("org.opencv.core.CvException", true, loader);
                exception.getConstructor(String.class);
            }
            results.putString("status", "pass");
            finish(Activity.RESULT_OK, results);
        } catch (ProbeUnsupported unsupported) {
            // R8 may inline, merge or specialize an entrypoint. Do not keep it just for a probe.
            results.putString("status", "unsupported-optimized-shape");
            results.putString("stage", stage);
            finish(Activity.RESULT_CANCELED, results);
        } catch (Throwable failure) {
            // Never emit messages, source-file/line stack traces, intent data, files or arguments.
            results.putString("status", "fail");
            results.putString("stage", stage);
            diagnostics(results, failure);
            results.putString("exception_type", boundedType(failure));
            Throwable cause = failure.getCause();
            if (cause != null) results.putString("cause_type", boundedType(cause));
            finish(Activity.RESULT_CANCELED, results);
        }
    }

    private static String symbol(String key, String fallback) throws ProbeUnsupported {
        if (!MAPPED) return fallback;
        for (String[] entry : SYMBOLS) if (entry[0].equals(key)) return entry[1];
        throw new ProbeUnsupported();
    }

    private static Class<?> targetClass(ClassLoader loader, String original) throws Exception {
        String name = symbol(original, original);
        if (name.contains("REMOVED")) throw new ProbeUnsupported();
        try { return Class.forName(name, true, loader); }
        catch (ClassNotFoundException missing) { throw new ProbeUnsupported(); }
    }

    private static Method targetMethod(Class<?> type, String holder, String original,
            Class<?>... parameters) throws Exception {
        String name = symbol(holder + "#" + original, original);
        try {
            Method method = type.getDeclaredMethod(name, parameters);
            method.setAccessible(true);
            return method;
        } catch (NoSuchMethodException missing) { throw new ProbeUnsupported(); }
    }

    private static void cryptoKnownAnswer(ClassLoader loader) throws Exception {
        String holder = "eu.opencloud.android.next.core.crypto.RcloneVaultCipher";
        stage = "crypto-load-class";
        Class<?> type = targetClass(loader, holder);
        stage = "crypto-read-lazy-field";
        Field lazyField;
        try { lazyField = type.getDeclaredField(symbol(holder + "#androidSecretBox$delegate",
                "androidSecretBox$delegate")); }
        catch (NoSuchFieldException missing) { throw new ProbeUnsupported(); }
        lazyField.setAccessible(true);
        Object lazy = lazyField.get(null);
        Class<?> lazyType = targetClass(loader, "kotlin.Lazy");
        stage = "crypto-initialize-target-secret-box";
        Object secretBox = targetMethod(lazyType, "kotlin.Lazy", "getValue").invoke(lazy);
        stage = "crypto-resolve-constructor";
        Constructor<?> constructor = null;
        for (Constructor<?> candidate : type.getDeclaredConstructors()) {
            Class<?>[] parameters = candidate.getParameterTypes();
            if (parameters.length == 2 && parameters[0] == byte[].class
                    && parameters[1].isInstance(secretBox)) constructor = candidate;
        }
        if (constructor == null) throw new ProbeUnsupported();
        constructor.setAccessible(true);
        byte[] material = new byte[80];
        stage = "crypto-construct-cipher";
        Object cipher = constructor.newInstance(material, secretBox);
        Method decrypt = targetMethod(type, holder, "decryptContent",
                java.io.InputStream.class, java.io.OutputStream.class, long.class);
        byte[] bytes = hex("52434c4f4e4500000102030405060708090a0b0c0d0e0f101112131415161718"
                + "095b446cd6237bbcb08d09fb524ce565aa");
        try {
            ByteArrayOutputStream plain = new ByteArrayOutputStream();
            stage = "crypto-decrypt-known-answer";
            Object count = decrypt.invoke(cipher, new ByteArrayInputStream(bytes), plain, 1L);
            if (!Long.valueOf(1L).equals(count) || !Arrays.equals(new byte[] {1}, plain.toByteArray()))
                throw new AssertionError();
            bytes[48] ^= 1;
            ByteArrayOutputStream rejected = new ByteArrayOutputStream();
            boolean denied = false;
            stage = "crypto-reject-tamper";
            try { decrypt.invoke(cipher, new ByteArrayInputStream(bytes), rejected, 1L); }
            catch (InvocationTargetException failure) {
                if (failure.getCause() instanceof SecurityException) denied = true;
                else throw failure;
            }
            if (!denied || rejected.size() != 0) throw new AssertionError();
        } finally {
            ((AutoCloseable) cipher).close();
            Arrays.fill(material, (byte) 0);
            Arrays.fill(bytes, (byte) 0);
        }
    }

    private void scanner(ClassLoader loader, boolean learned) throws Exception {
        String holder = learned ? "dev.offlinescan.processing.LearnedDocumentDetector"
                : "dev.offlinescan.processing.OpenCvProcessor";
        stage = "scanner-load-class";
        Class<?> type = targetClass(loader, holder);
        stage = "scanner-construct-detector";
        Object detector;
        try {
            detector = learned ? type.getConstructor(android.content.Context.class)
                    .newInstance(getTargetContext()) : standardProcessor(loader);
        } catch (NoSuchMethodException missing) { throw new ProbeUnsupported(); }
        stage = "scanner-resolve-specific-method";
        // Enumerating every method resolves unrelated API28 ImageDecoder signatures
        // in OpenCvProcessor on API26. Resolve only this known interface signature.
        Class<?> cancellationType = targetClass(loader, "dev.offlinescan.core.Cancellation");
        if (!cancellationType.isInterface()) throw new ProbeUnsupported();
        Method detect = targetMethod(type, holder, "detectBitmap", Bitmap.class, cancellationType);
        stage = "scanner-create-cancellation-proxy";
        Object cancellation = Proxy.newProxyInstance(loader, new Class<?>[] {cancellationType},
                new InvocationHandler() {
                    @Override public Object invoke(Object proxy, Method method, Object[] args) {
                        if (method.getReturnType() == void.class) return null;
                        if (method.getName().equals("hashCode")) return System.identityHashCode(proxy);
                        if (method.getName().equals("equals")) return proxy == args[0];
                        if (method.getName().equals("toString")) return "Synthetic cancellation";
                        throw new UnsupportedOperationException();
                    }
                });
        Bitmap bitmap = Bitmap.createBitmap(640, 480, Bitmap.Config.ARGB_8888);
        try {
            Canvas canvas = new Canvas(bitmap);
            canvas.drawColor(Color.rgb(32, 36, 40));
            Paint paint = new Paint();
            paint.setColor(Color.WHITE);
            canvas.drawRect(100, 50, 540, 430, paint);
            paint.setColor(Color.BLACK);
            paint.setStrokeWidth(3);
            for (int y = 100; y < 390; y += 20) canvas.drawLine(140, y, 490, y, paint);
            stage = "scanner-run-target-detection";
            Object detection = detect.invoke(detector, bitmap, cancellation);
            if (detection == null) throw new AssertionError();
            // These are actual result fields, not test-added getters/retention roots.
            stage = "scanner-read-result-metrics";
            String detectionHolder = "dev.offlinescan.core.Detection";
            Class<?> detectionType = targetClass(loader, detectionHolder);
            for (String metric : new String[] {"confidence", "brightness", "sharpness"}) {
                Field field;
                try { field = detectionType.getDeclaredField(symbol(detectionHolder + "#" + metric, metric)); }
                catch (NoSuchFieldException missing) { throw new ProbeUnsupported(); }
                field.setAccessible(true);
                double value = field.getDouble(detection);
                if (Double.isNaN(value) || Double.isInfinite(value)) throw new AssertionError();
            }
            // Both detectors load the target OpenCV, so exercise its native error ABI too.
            nativeOpenCvException(loader);
        } finally {
            bitmap.recycle();
            if (detector instanceof AutoCloseable) ((AutoCloseable) detector).close();
        }
    }

    private Object standardProcessor(ClassLoader loader) throws Exception {
        Class<?> processor = targetClass(loader, "dev.offlinescan.processing.OpenCvProcessor");
        try { return processor.getConstructor().newInstance(); }
        catch (NoSuchMethodException missing) {
            // R8 can remove the empty constructor and initialize this stateless object
            // via Object.<init>. Use the scanner's own surviving construction path.
            String holder = "dev.offlinescan.processing.LearnedDocumentDetector";
            Object owner = targetClass(loader, holder).getConstructor(android.content.Context.class)
                    .newInstance(getTargetContext());
            try {
                Object result = targetField(owner, holder, "quality");
                if (!processor.isInstance(result)) throw new ProbeUnsupported();
                return result;
            } finally { if (owner instanceof AutoCloseable) ((AutoCloseable) owner).close(); }
        }
    }

    private static Object targetField(Object owner, String holder, String name) throws Exception {
        Field field;
        try { field = owner.getClass().getDeclaredField(symbol(holder + "#" + name, name)); }
        catch (NoSuchFieldException missing) { throw new ProbeUnsupported(); }
        field.setAccessible(true);
        return field.get(owner);
    }

    private static Object targetConstant(ClassLoader loader, String holder, String name) throws Exception {
        Field field = targetClass(loader, holder).getDeclaredField(symbol(holder + "#" + name, name));
        field.setAccessible(true);
        return field.get(null);
    }

    private static Object callback(ClassLoader loader, Class<?> type, final AtomicBoolean cancel)
            throws Exception {
        if (!type.isInterface()) throw new ProbeUnsupported();
        return Proxy.newProxyInstance(loader, new Class<?>[] {type}, new InvocationHandler() {
            @Override public Object invoke(Object proxy, Method method, Object[] args) {
                if (method.getReturnType() == void.class) {
                    if (cancel != null && cancel.get()) throw new CancellationException();
                    return null;
                }
                if (method.getName().equals("hashCode")) return System.identityHashCode(proxy);
                if (method.getName().equals("equals")) return proxy == args[0];
                if (method.getName().equals("toString")) return "Synthetic scanner callback";
                throw new UnsupportedOperationException();
            }
        });
    }

    private static String sha256(File file) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        try (FileInputStream stream = new FileInputStream(file)) {
            byte[] buffer = new byte[65536];
            int count;
            while ((count = stream.read(buffer)) != -1) digest.update(buffer, 0, count);
        }
        StringBuilder result = new StringBuilder();
        for (byte b : digest.digest()) result.append(String.format(java.util.Locale.US, "%02x", b & 255));
        return result.toString();
    }

    private static void deleteOwned(File file) throws Exception {
        File[] children = file.listFiles();
        if (children != null) for (File child : children) deleteOwned(child);
        if (file.exists() && !file.delete()) throw new AssertionError();
    }

    private static File onlyExportFile(Object output, String mime, int pages) throws Exception {
        String holder = "dev.offlinescan.core.ScanOutput";
        if (!mime.equals(targetField(output, holder, "mimeType"))) throw new AssertionError();
        List<?> files = (List<?>) targetField(output, holder, "files");
        List<?> sizes = (List<?>) targetField(output, holder, "pages");
        if (files.size() != 1 || sizes.size() != pages) throw new AssertionError();
        for (Object size : sizes) {
            String pageHolder = "dev.offlinescan.core.ExportedPage";
            if (!Integer.valueOf(2300).equals(targetField(size, pageHolder, "width"))
                    || !Integer.valueOf(3100).equals(targetField(size, pageHolder, "height")))
                throw new AssertionError();
        }
        File result = (File) files.get(0);
        File[] siblings = result.getParentFile().listFiles();
        if (!result.isFile() || siblings == null || siblings.length != 1) throw new AssertionError();
        return result;
    }

    private void scannerExport(ClassLoader loader) throws Exception {
        stage = "export-check-exact-apk-recipe";
        if (MAPPED && (SCANNER_SHAPE.length != 8 || !SCANNER_SHAPE[0].equals(
                sha256(new File(getTargetContext().getApplicationInfo().sourceDir)))))
            throw new ProbeUnsupported();
        stage = "export-construct-target-processor";
        Object processor = standardProcessor(loader);
        Class<?> configType = targetClass(loader, "dev.offlinescan.core.ScanConfig");
        Class<?> modeType = targetClass(loader, "dev.offlinescan.core.ScanMode");
        Class<?> detectionType = targetClass(loader, "dev.offlinescan.core.DetectionMode");
        Object mode = targetConstant(loader, "dev.offlinescan.core.ScanMode", "DOCUMENT");
        Object detectionMode = targetConstant(loader, "dev.offlinescan.core.DetectionMode", "STANDARD");
        stage = "export-construct-explicit-config";
        // R8 removes the always-false cardFrontBack parameter; the supplied recipe
        // is bound to inspected DEX, not an arity-based constructor guess.
        Object config = MAPPED ? configType.getConstructor(modeType, int.class, long.class,
                int.class, int.class, boolean.class, detectionType, long.class, long.class)
                .newInstance(mode, 2, 32000000L, 4096, 95, false, detectionMode, 16000000L, 268435456L)
                : configType.getConstructor(modeType, int.class, long.class, int.class, int.class,
                boolean.class, boolean.class, detectionType, long.class, long.class)
                .newInstance(mode, 2, 32000000L, 4096, 95, false, false, detectionMode, 16000000L, 268435456L);
        Class<?> quadType = targetClass(loader, "dev.offlinescan.core.Quad");
        Class<?> presetType = targetClass(loader, "dev.offlinescan.core.Preset");
        Class<?> editsType = targetClass(loader, "dev.offlinescan.core.Edits");
        Object full = targetConstant(loader, "dev.offlinescan.core.Quad", "FULL");
        Object original = targetConstant(loader, "dev.offlinescan.core.Preset", "ORIGINAL");
        Object edits = editsType.getConstructor(quadType, int.class, presetType,
                double.class, double.class, double.class).newInstance(full, 0, original, 0d, 1d, 0d);
        Class<?> pageType = targetClass(loader, "dev.offlinescan.core.ScanPage");
        Class<?> formatType = targetClass(loader, "dev.offlinescan.core.ExportFormat");
        AtomicBoolean cancel = new AtomicBoolean(false);
        Object exporter;
        Object cancellation;
        Object progress;
        Method export;
        stage = "export-resolve-target-exporter";
        if (MAPPED) {
            Class<?> exporterType = Class.forName(SCANNER_SHAPE[1], true, loader);
            Class<?> cancellationType = Class.forName(SCANNER_SHAPE[3], true, loader);
            Class<?> progressType = Class.forName(SCANNER_SHAPE[5], true, loader);
            Class<?> progressState = Class.forName(SCANNER_SHAPE[7], true, loader);
            exporter = exporterType.getConstructor(processor.getClass()).newInstance(processor);
            cancellation = cancellationType.getConstructor(int.class, Object.class)
                    .newInstance(Integer.parseInt(SCANNER_SHAPE[4]), cancel);
            progress = progressType.getConstructor(int.class, Object.class)
                    .newInstance(Integer.parseInt(SCANNER_SHAPE[6]), progressState.getConstructor(float.class)
                            .newInstance(0f));
            export = exporterType.getDeclaredMethod(SCANNER_SHAPE[2], List.class, File.class,
                    formatType, configType, cancellationType, progressType, String.class);
        } else {
            Class<?> exporterType = targetClass(loader, "dev.offlinescan.export.AndroidExporter");
            Class<?> processorInterface = targetClass(loader, "dev.offlinescan.core.ImageProcessor");
            Class<?> cancellationType = targetClass(loader, "dev.offlinescan.core.Cancellation");
            Class<?> progressType = targetClass(loader, "dev.offlinescan.core.Progress");
            exporter = exporterType.getConstructor(processorInterface).newInstance(processor);
            cancellation = callback(loader, cancellationType, cancel);
            progress = callback(loader, progressType, null);
            export = exporterType.getDeclaredMethod("export", List.class, File.class,
                    formatType, configType, cancellationType, progressType, String.class, boolean.class);
        }
        export.setAccessible(true);
        File root = File.createTempFile("raiun-r8-scanner-", "", getTargetContext().getCacheDir());
        if (!root.delete() || !root.mkdir()) throw new AssertionError();
        try {
            File inputs = new File(root, "inputs");
            if (!inputs.mkdir()) throw new AssertionError();
            File source = new File(inputs, "printed.png");
            Bitmap bitmap = Bitmap.createBitmap(2300, 3100, Bitmap.Config.ARGB_8888);
            try {
                Canvas canvas = new Canvas(bitmap);
                canvas.drawColor(Color.WHITE);
                Paint ink = new Paint(Paint.ANTI_ALIAS_FLAG);
                ink.setColor(Color.BLACK);
                ink.setTextSize(32f);
                for (int row = 0; row < 24; row++) canvas.drawText(
                        "SCAN DETAIL 0123456789 abcdefghijklmnopqrstuvwxyz", 90f, 200f + row * 105f, ink);
                canvas.drawRect(100f, 450f, 200f, 550f, ink);
                try (FileOutputStream sink = new FileOutputStream(source)) {
                    if (!bitmap.compress(Bitmap.CompressFormat.PNG, 100, sink)) throw new AssertionError();
                }
            } finally { bitmap.recycle(); }
            String sourceHash = sha256(source);
            ArrayList<Object> pages = new ArrayList<Object>();
            Constructor<?> pageConstructor = pageType.getConstructor(String.class, File.class,
                    int.class, int.class, editsType);
            pages.add(pageConstructor.newInstance("synthetic-first", source, 2300, 3100, edits));
            pages.add(pageConstructor.newInstance("synthetic-second", source, 2300, 3100, edits));
            File destination = new File(root, "output");
            Object jpeg = targetConstant(loader, "dev.offlinescan.core.ExportFormat", "JPEG");
            Object pdf = targetConstant(loader, "dev.offlinescan.core.ExportFormat", "PDF");
            stage = "export-native-jpeg";
            ArrayList<Object> first = new ArrayList<Object>(pages.subList(0, 1));
            Object jpegOutput = invokeExport(export, exporter, first, destination, jpeg, config, cancellation, progress);
            File jpegFile = onlyExportFile(jpegOutput, "image/jpeg", 1);
            stage = "export-parse-jpeg-dimensions-and-content";
            BitmapFactory.Options bounds = new BitmapFactory.Options();
            bounds.inJustDecodeBounds = true;
            BitmapFactory.decodeFile(jpegFile.getPath(), bounds);
            if (bounds.outWidth != 2300 || bounds.outHeight != 3100) throw new AssertionError();
            Bitmap rendered = BitmapFactory.decodeFile(jpegFile.getPath());
            if (rendered == null) throw new AssertionError();
            try {
                if (Color.red(rendered.getPixel(70, 70)) <= 240
                        || Color.red(rendered.getPixel(150, 500)) >= 100) throw new AssertionError();
            } finally { rendered.recycle(); }
            stage = "export-native-two-page-pdf";
            Object pdfOutput = invokeExport(export, exporter, pages, destination, pdf, config, cancellation, progress);
            File pdfFile = onlyExportFile(pdfOutput, "application/pdf", 2);
            stage = "export-parse-pdf-page-and-image-dimensions";
            try (ParcelFileDescriptor descriptor = ParcelFileDescriptor.open(pdfFile, ParcelFileDescriptor.MODE_READ_ONLY);
                    PdfRenderer parser = new PdfRenderer(descriptor)) {
                if (parser.getPageCount() != 2) throw new AssertionError();
                for (int i = 0; i < 2; i++) try (PdfRenderer.Page page = parser.openPage(i)) {
                    if (page.getWidth() != 552 || page.getHeight() != 744) throw new AssertionError();
                }
            }
            ByteArrayOutputStream pdfBytes = new ByteArrayOutputStream();
            try (FileInputStream stream = new FileInputStream(pdfFile)) {
                byte[] buffer = new byte[65536]; int count;
                while ((count = stream.read(buffer)) != -1) pdfBytes.write(buffer, 0, count);
            }
            String pdfText = new String(pdfBytes.toByteArray(), "ISO-8859-1");
            java.util.regex.Matcher images = java.util.regex.Pattern.compile(
                    "/Subtype /Image /Width 2300 /Height 3100\\b").matcher(pdfText);
            int imageCount = 0;
            while (images.find()) imageCount++;
            if (imageCount != 2) throw new AssertionError();
            stage = "export-cancel-and-remove-staging";
            cancel.set(true);
            File cancelled = new File(root, "cancelled-output");
            boolean denied = false;
            try { invokeExport(export, exporter, pages, cancelled, jpeg, config, cancellation, progress); }
            catch (InvocationTargetException failure) {
                if (failure.getCause() instanceof CancellationException) denied = true;
                else throw failure;
            }
            File[] abandoned = cancelled.listFiles();
            if (!denied || abandoned == null || abandoned.length != 0) throw new AssertionError();
            stage = "export-verify-source-ownership";
            File[] outputs = destination.listFiles();
            if (outputs == null || outputs.length != 2 || !sourceHash.equals(sha256(source)))
                throw new AssertionError();
            nativeOpenCvException(loader);
        } finally {
            deleteOwned(root);
            if (processor instanceof AutoCloseable) ((AutoCloseable) processor).close();
        }
    }

    private static Object invokeExport(Method method, Object exporter, List<?> pages, File destination,
            Object format, Object config, Object cancellation, Object progress) throws Exception {
        return MAPPED ? method.invoke(exporter, pages, destination, format, config, cancellation, progress, null)
                : method.invoke(exporter, pages, destination, format, config, cancellation, progress, null, false);
    }

    private static void nativeOpenCvException(ClassLoader loader) throws Exception {
        // The standard scanner above loads the target's native OpenCV. This private
        // native method keeps its exact JNI name under Android's default rule.
        stage = "scanner-native-exception";
        Class<?> mat = Class.forName("org.opencv.core.Mat", true, loader);
        Method allocate;
        try { allocate = mat.getDeclaredMethod("n_Mat", int.class, int.class, int.class); }
        catch (NoSuchMethodException missing) { throw new ProbeUnsupported(); }
        allocate.setAccessible(true);
        boolean denied = false;
        try { allocate.invoke(null, -1, -1, 0); }
        catch (InvocationTargetException failure) {
            if (failure.getCause() != null && failure.getCause().getClass().getName()
                    .equals("org.opencv.core.CvException")) denied = true;
            else throw failure;
        }
        if (!denied) throw new AssertionError();
    }


    private Object parseSettings(Class<?> type, String holder, File file) throws Exception {
        String name = symbol(holder + "#parseFrom", "parseFrom");
        Method parse = null;
        // R8 narrows the app's sole InputStream caller to FileInputStream.
        for (Class<?> parameter : new Class<?>[] {FileInputStream.class, java.io.InputStream.class}) {
            try { parse = type.getDeclaredMethod(name, parameter); break; }
            catch (NoSuchMethodException ignored) { }
        }
        if (parse == null) throw new ProbeUnsupported();
        parse.setAccessible(true);
        try (FileInputStream input = new FileInputStream(file)) { return parse.invoke(null, input); }
    }

    private static void checkSettings(Object settings) throws Exception {
        String[] names = {"browserLayout_", "activeAccountId_", "cacheRetentionDays_",
                "localDiagnosticsEnabled_", "appearance_", "temporaryCopyRetentionHours_",
                "hideFileSize_", "hideModifiedDate_", "hideFileExtensions_", "showHiddenFiles_",
                "externalText_", "externalPdf_", "externalImages_", "pinnedNavigationItems_"};
        Object[] expected = {3, "synthetic-r8-account", 30, true, 2, 24,
                true, true, true, true, true, true, true, Arrays.asList("R8_FIRST", "R8_SECOND")};
        for (int i = 0; i < names.length; i++) {
            // These exact field names are the runtime protobuf schema ABI, not probe roots.
            Field field = settings.getClass().getDeclaredField(names[i]);
            field.setAccessible(true);
            if (!expected[i].equals(field.get(settings))) throw new AssertionError();
        }
    }

    private void protobufRoundtrip(ClassLoader loader) throws Exception {
        String holder = "eu.opencloud.android.next.core.datastore.proto.AppSettings";
        stage = "protobuf-load-target";
        Class<?> settingsType = targetClass(loader, holder);
        byte[] wire = hex("0803121473796e7468657469632d72382d6163636f756e74181e2001280230183801400148015001580160016801720852385f4649525354720952385f5345434f4e44");
        File inputFile = File.createTempFile("raiun-r8-protobuf-in-", ".pb", getTargetContext().getCacheDir());
        File outputFile = File.createTempFile("raiun-r8-protobuf-out-", ".pb", getTargetContext().getCacheDir());
        try {
            try (FileOutputStream input = new FileOutputStream(inputFile)) { input.write(wire); }
            stage = "protobuf-parse-known-wire";
            Object settings = parseSettings(settingsType, holder, inputFile);
            checkSettings(settings);

            stage = "protobuf-resolve-target-schema";
            String protobufHolder = "com.google.protobuf.Protobuf";
            Class<?> protobufType = targetClass(loader, protobufHolder);
            Field instance = protobufType.getDeclaredField(symbol(protobufHolder + "#INSTANCE", "INSTANCE"));
            instance.setAccessible(true);
            Object protobuf = instance.get(null);
            Object schema = targetMethod(protobufType, protobufHolder, "schemaFor", Class.class)
                    .invoke(protobuf, settingsType);
            String schemaHolder = "com.google.protobuf.MessageSchema";
            String writeName = symbol(schemaHolder + "#writeTo", "writeTo");
            Method write = null;
            for (Method method : schema.getClass().getDeclaredMethods()) {
                Class<?>[] parameters = method.getParameterTypes();
                if (method.getName().equals(writeName) && parameters.length == 2
                        && parameters[0] == Object.class) write = method;
            }
            if (write == null) throw new ProbeUnsupported();
            write.setAccessible(true);

            stage = "protobuf-construct-target-encoder";
            String encoderHolder = "com.google.protobuf.CodedOutputStream$OutputStreamEncoder";
            Class<?> encoderType = targetClass(loader, encoderHolder);
            try (FileOutputStream output = new FileOutputStream(outputFile)) {
                Object encoder = null;
                for (Constructor<?> constructor : encoderType.getDeclaredConstructors()) {
                    Class<?>[] parameters = constructor.getParameterTypes();
                    if (parameters.length != 2 || parameters[1] != int.class) continue;
                    Object sink = output;
                    if (!parameters[0].isInstance(sink)) {
                        // Optimized DataStore encoder uses its actual UncloseableOutputStream
                        // wrapper, which may be merged/renamed. Infer its type from the live
                        // constructor, then require the real FileOutputStream constructor.
                        Constructor<?> wrapper;
                        try { wrapper = parameters[0].getDeclaredConstructor(FileOutputStream.class); }
                        catch (NoSuchMethodException missing) { continue; }
                        wrapper.setAccessible(true);
                        sink = wrapper.newInstance(output);
                    }
                    constructor.setAccessible(true);
                    encoder = constructor.newInstance(sink, 4096);
                    break;
                }
                if (encoder == null) throw new ProbeUnsupported();
                stage = "protobuf-construct-target-writer";
                Class<?> writerType = write.getParameterTypes()[1];
                // In the unshrunk control the parameter is Writer; minimized code can
                // narrow it directly to the concrete (possibly merged) target writer.
                if (writerType.isInterface())
                    writerType = Class.forName("com.google.protobuf.CodedOutputStreamWriter", true, loader);
                Object writer = null;
                for (Constructor<?> constructor : writerType.getDeclaredConstructors()) {
                    Class<?>[] parameters = constructor.getParameterTypes();
                    if (parameters.length == 1 && parameters[0].isInstance(encoder)) {
                        constructor.setAccessible(true);
                        writer = constructor.newInstance(encoder);
                        break;
                    }
                }
                if (writer == null) throw new ProbeUnsupported();
                stage = "protobuf-serialize-target-message";
                write.invoke(schema, settings, writer);
                // flush() may inline into DataStore; the target encoder's doFlush is
                // its surviving actual buffer-to-stream implementation in both shapes.
                targetMethod(encoderType, encoderHolder, "doFlush").invoke(encoder);
                output.flush();
            }
            stage = "protobuf-verify-wire-and-reparse";
            ByteArrayOutputStream serialized = new ByteArrayOutputStream();
            try (FileInputStream output = new FileInputStream(outputFile)) {
                byte[] buffer = new byte[256];
                int count;
                while ((count = output.read(buffer)) != -1) {
                    if (serialized.size() + count > 4096) throw new AssertionError();
                    serialized.write(buffer, 0, count);
                }
            }
            if (!Arrays.equals(wire, serialized.toByteArray())) throw new AssertionError();
            checkSettings(parseSettings(settingsType, holder, outputFile));
        } finally {
            // Only the two File.createTempFile results are touched; never settings storage.
            inputFile.delete();
            outputFile.delete();
            Arrays.fill(wire, (byte) 0);
        }
    }

    private static byte[] hex(String text) {
        byte[] bytes = new byte[text.length() / 2];
        for (int i = 0; i < bytes.length; i++) bytes[i] = (byte) Integer.parseInt(text.substring(i*2, i*2+2), 16);
        return bytes;
    }

    private static String safeName(String value) {
        // Identifiers only: never file names, messages, paths or arbitrary toString().
        String safe = value.replaceAll("[^A-Za-z0-9_.$<>]", "_");
        return safe.length() <= 160 ? safe : safe.substring(0, 160);
    }

    private static void diagnostics(Bundle results, Throwable failure) {
        Throwable current = failure;
        for (int depth = 0; current != null && depth < 6; depth++) {
            results.putString("chain_type_" + depth, boundedType(current));
            StackTraceElement[] frames = current.getStackTrace();
            StringBuilder names = new StringBuilder();
            for (int i = 0; i < frames.length && i < 8; i++) {
                if (i != 0) names.append(",");
                names.append(safeName(frames[i].getClassName())).append("#")
                        .append(safeName(frames[i].getMethodName()));
            }
            results.putString("chain_frames_" + depth, names.toString());
            Throwable next = current.getCause();
            if (next == current) break;
            current = next;
        }
    }

    private static String boundedType(Throwable failure) {
        String type = failure.getClass().getName();
        return type.length() <= 160 ? type : type.substring(0, 160);
    }
}
'''


def mapped_symbols(mapping: Path | None) -> dict[str, str]:
    """Extract names only; runtime checks residual signatures instead of guessing them.

    Mapping records for inlined methods have qualified names and are ignored.
    Ambiguous names are omitted, resulting in unsupported-optimized-shape.
    This is intentionally not a general-purpose R8 retracer.
    """
    if mapping is None:
        return {}
    symbols: dict[str, set[str]] = {}
    holder = ""
    for line in mapping.read_text(encoding="utf-8").splitlines():
        if line and not line[0].isspace() and not line.startswith("#"):
            match = re.fullmatch(r"(.+) -> (.+):", line)
            if match:
                holder, renamed = match.groups()
                symbols.setdefault(holder, set()).add(renamed)
        elif holder and " -> " in line and not line.lstrip().startswith("#"):
            original, renamed = line.strip().rsplit(" -> ", 1)
            original = re.sub(r"^\d+:\d+:", "", original)
            if "(" in original:
                original = original.split("(", 1)[0].rsplit(" ", 1)[-1]
            else:
                original = original.rsplit(" ", 1)[-1]
            if "." not in original:
                symbols.setdefault(holder + "#" + original, set()).add(renamed)
    return {key: next(iter(values)) for key, values in symbols.items() if len(values) == 1}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", required=True, type=Path)
    parser.add_argument("--java-home", required=True, type=Path)
    parser.add_argument("--keystore", required=True, type=Path)
    parser.add_argument("--key-alias", required=True)
    parser.add_argument("--compile-sdk", required=True, type=int)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--mapping", type=Path, help="Exact target R8 mapping; omit only for an unshrunk control")
    parser.add_argument("--scanner-shape", type=Path,
                        help="Reviewed exact-APK residual export recipe, bound to mapping and installed APK hashes")
    args = parser.parse_args()
    if os.environ.get("FIXTURE_STORE_PASSWORD") != "android":
        raise SystemExit("Only the standard Android debug-key password is supported")
    if not args.keystore.is_file():
        raise SystemExit("The existing standard Android debug keystore is missing")
    sdk = sdk_directory(args.project)
    tools = newest(sdk / "build-tools", ("aapt", "zipalign", "lib/apksigner.jar", "lib/d8.jar"))
    platform = sdk / "platforms" / f"android-{args.compile_sdk}" / "android.jar"
    if not platform.is_file():
        raise SystemExit("Compile SDK platform is missing")
    java = args.java_home / "bin" / "java"
    javac = args.java_home / "bin" / "javac"
    args.output.mkdir(parents=True, exist_ok=True)
    scanner_shape = []
    if args.scanner_shape:
        recipe = json.loads(args.scanner_shape.read_text(encoding="utf-8"))
        if not args.mapping or recipe["mapping_sha256"] != hashlib.sha256(args.mapping.read_bytes()).hexdigest():
            raise SystemExit("Scanner residual recipe does not match the exact supplied mapping")
        scanner_shape = [recipe[key] for key in (
            "apk_sha256", "export_holder", "export_method", "cancellation_class",
            "cancellation_discriminator", "progress_class", "progress_discriminator", "progress_state_class")]
        if not re.fullmatch(r"[0-9a-f]{64}", scanner_shape[0]):
            raise SystemExit("Scanner residual recipe has no exact APK hash")
        scanner_shape = [str(value) for value in scanner_shape]
    with tempfile.TemporaryDirectory(prefix="raiun-r8-probe-") as directory:
        work = Path(directory)
        source = work / "R8ProbeInstrumentation.java"
        # Include only probe-owned symbol keys, rather than the full app mapping.
        holders = {
            "eu.opencloud.android.next.core.crypto.RcloneVaultCipher":
                {"androidSecretBox$delegate", "decryptContent"},
            "kotlin.Lazy": {"getValue"},
            "dev.offlinescan.processing.OpenCvProcessor": {"detectBitmap"},
            "dev.offlinescan.processing.LearnedDocumentDetector": {"detectBitmap", "quality"},
            "dev.offlinescan.core.Detection": {"confidence", "brightness", "sharpness"},
            "dev.offlinescan.core.Cancellation": set(),
            "dev.offlinescan.core.ScanConfig": set(),
            "dev.offlinescan.core.ScanMode": {"DOCUMENT"},
            "dev.offlinescan.core.DetectionMode": {"STANDARD"},
            "dev.offlinescan.core.Quad": {"FULL"},
            "dev.offlinescan.core.Preset": {"ORIGINAL"},
            "dev.offlinescan.core.Edits": set(),
            "dev.offlinescan.core.ScanPage": set(),
            "dev.offlinescan.core.ExportFormat": {"JPEG", "PDF"},
            "dev.offlinescan.core.ScanOutput": {"files", "mimeType", "pages"},
            "dev.offlinescan.core.ExportedPage": {"width", "height"},
            "eu.opencloud.android.next.core.datastore.proto.AppSettings": {"parseFrom"},
            "com.google.protobuf.Protobuf": {"INSTANCE", "schemaFor"},
            "com.google.protobuf.MessageSchema": {"writeTo"},
            "com.google.protobuf.CodedOutputStream$OutputStreamEncoder": {"doFlush"},
        }
        all_symbols = mapped_symbols(args.mapping)
        keys = set(holders) | {holder + "#" + member for holder, members in holders.items() for member in members}
        symbols = {key: value for key, value in all_symbols.items() if key in keys}
        literal = "{" + ",".join("{" + json.dumps(key) + "," + json.dumps(value) + "}"
                                  for key, value in sorted(symbols.items())) + "}"
        source.write_text(SOURCE.replace("__MAPPED_SYMBOLS__", literal).replace(
            "__HAS_MAPPING__", str(args.mapping is not None).lower()).replace(
            "__SCANNER_SHAPE__", "{" + ",".join(json.dumps(value) for value in scanner_shape) + "}"), encoding="utf-8")
        (args.output / "probe-symbols.json").write_text(json.dumps({
            "mapping_sha256": hashlib.sha256(args.mapping.read_bytes()).hexdigest() if args.mapping else None,
            "symbols": symbols,
            "scanner_shape": json.loads(args.scanner_shape.read_text()) if args.scanner_shape else None,
            "boundary": "No keep roots added; optimized entrypoint shapes can be unsupported. A successful learned call runs the target bundled model; it is not a scanner quality assertion.",
        }, indent=2) + "\n", encoding="utf-8")
        classes = work / "classes"
        classes.mkdir()
        run(
            str(javac), "-source", "8", "-target", "8", "-bootclasspath", str(platform),
            "-d", str(classes), str(source),
        )
        dex = work / "dex"
        dex.mkdir()
        run(
            str(java), "-cp", str(tools / "lib/d8.jar"), "com.android.tools.r8.D8",
            "--min-api", "26", "--lib", str(platform), "--output", str(dex),
            *map(str, sorted(classes.rglob("*.class"))),
        )
        manifest = work / "AndroidManifest.xml"
        manifest.write_text(
            '<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
            f'package="{PACKAGE}" android:versionCode="1" android:versionName="1">'
            '<uses-sdk android:minSdkVersion="26" android:targetSdkVersion="35"/>'
            '<application android:label="Synthetic framework R8 probe" '
            'android:debuggable="true" android:allowBackup="false"/>'
            f'<instrumentation android:name="{PACKAGE}.R8ProbeInstrumentation" '
            f'android:targetPackage="{TARGET_PACKAGE}" android:functionalTest="true"/>'
            '</manifest>', encoding="utf-8",
        )
        unsigned = work / "unsigned.apk"
        run(
            str(tools / "aapt"), "package", "-f", "-M", str(manifest),
            "-I", str(platform), "-F", str(unsigned),
        )
        with zipfile.ZipFile(unsigned, "a") as apk:
            apk.write(dex / "classes.dex", "classes.dex")
        aligned = work / "aligned.apk"
        run(str(tools / "zipalign"), "-f", "4", str(unsigned), str(aligned))
        result = args.output / "r8-probe-fixture.apk"
        run(
            str(java), "-jar", str(tools / "lib/apksigner.jar"), "sign", "--ks", str(args.keystore),
            "--ks-key-alias", args.key_alias, "--ks-pass", "env:FIXTURE_STORE_PASSWORD",
            "--key-pass", "env:FIXTURE_STORE_PASSWORD", "--out", str(result), str(aligned),
        )
        run(str(java), "-jar", str(tools / "lib/apksigner.jar"), "verify", str(result))


if __name__ == "__main__":
    main()
