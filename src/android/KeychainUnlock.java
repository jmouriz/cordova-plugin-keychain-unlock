package ar.com.tecnologica.KeychainUnlock;

import org.apache.cordova.CordovaWebView;
import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.CordovaInterface;
import org.apache.cordova.PluginResult;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import android.Manifest;
import android.annotation.TargetApi;
import android.app.Activity;
import android.app.KeyguardManager;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.content.res.Configuration;
import android.content.res.Resources;
import android.os.Bundle;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.security.keystore.KeyPermanentlyInvalidatedException;
import android.util.Base64;
import android.util.DisplayMetrics;
import android.util.Log;

import java.security.InvalidKeyException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.SecureRandom;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import java.util.regex.Pattern;

import java.io.IOException;
import java.io.UnsupportedEncodingException;

@TargetApi(23)
public class KeychainUnlock extends CordovaPlugin {
    public static final String TAG = "KeychainUnlock";
    public static String packageName;
    public static Context mContext;
    public static Activity mActivity;
    public static KeyStore mKeyStore;
    public static KeyGenerator mKeyGenerator;
    public static Cipher mCipher;
    public static CallbackContext mCallbackContext;
    public static PluginResult mPluginResult;
    public boolean mEncryptNoAuth = false;
    public KeyguardManager mKeyguardManager;

    private static final String SAVE = "save";
    private static final String VERIFY = "verify";
    private static final String AVAILABLE = "available";
    private static final String HAS = "has";
    private static final String DELETE = "delete";
    private static final String UPDATE = "update";
 
    private static final String CLIENT_ID = "KeychainUnlock"; // XXX
    private static final String ANDROID_KEY_STORE = "AndroidKeyStore";
    private static final int REQUEST_CODE_CONFIRM_DEVICE_CREDENTIALS = 1;
    private static final String CREDENTIAL_DELIMITER = "|:|";
    private static final String SHARED_PREFS_NAME = "KeychainUnlockPreferences";
    private static String mKeyID;
    private String mToEncrypt;

    public enum PluginError {
        BAD_PADDING_EXCEPTION,
        CERTIFICATE_EXCEPTION,
        ILLEGAL_BLOCK_SIZE_EXCEPTION,
        INIT_CIPHER_FAILED,
        INVALID_ALGORITHM_PARAMETER_EXCEPTION,
        IO_EXCEPTION,
        JSON_EXCEPTION,
        MINIMUM_SDK,
        MISSING_ACTION_PARAMETERS,
        MISSING_PARAMETERS,
        NO_SUCH_ALGORITHM_EXCEPTION,
        SECURITY_EXCEPTION
    }

    public KeychainUnlock() {
    }

    /**
     * Sets the context of the Command. This can then be used to do things like
     * get file paths associated with the Activity.
     *
     * @param cordova The context of the main Activity.
     * @param webView The CordovaWebView Cordova is running in.
     */
    public void initialize(CordovaInterface cordova, CordovaWebView webView) {
        super.initialize(cordova, webView);
        Log.v(TAG, "Init KeychainUnlock");

        packageName = cordova.getActivity().getApplicationContext().getPackageName();
        mPluginResult = new PluginResult(PluginResult.Status.NO_RESULT);
        mActivity = cordova.getActivity();
        mContext = cordova.getActivity().getApplicationContext();

        if (android.os.Build.VERSION.SDK_INT < 23) {
            return;
        }

        mKeyguardManager = cordova.getActivity().getSystemService(KeyguardManager.class);

        try {
            mKeyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEY_STORE);
            mKeyStore = KeyStore.getInstance(ANDROID_KEY_STORE);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Failed to get an instance of KeyGenerator", e);
        } catch (NoSuchProviderException e) {
            throw new RuntimeException("Failed to get an instance of KeyGenerator", e);
        } catch (KeyStoreException e) {
            throw new RuntimeException("Failed to get an instance of KeyStore", e);
        }

        try {
            mCipher = Cipher.getInstance(KeyProperties.KEY_ALGORITHM_AES + "/" + KeyProperties.BLOCK_MODE_CBC + "/" + KeyProperties.ENCRYPTION_PADDING_PKCS7);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Failed to get an instance of Cipher", e);
        } catch (NoSuchPaddingException e) {
            throw new RuntimeException("Failed to get an instance of Cipher", e);
        }
    }

    /**
     * Executes the request and returns PluginResult.
     *
     * @param action          The action to execute.
     * @param args            JSONArray of arguments for the plugin.
     * @param callbackContext The callback id used when calling back into JavaScript.
     * @return A PluginResult object with a status and message.
     */
    public boolean execute(final String action, JSONArray args, CallbackContext callbackContext) throws JSONException {
        mCallbackContext = callbackContext;

        if (android.os.Build.VERSION.SDK_INT < 23) {
            Log.e(TAG, "minimum SDK version 23 required");
            mPluginResult = new PluginResult(PluginResult.Status.ERROR);
            mCallbackContext.error(PluginError.MINIMUM_SDK.name());
            mCallbackContext.sendPluginResult(mPluginResult);
            return true;
        }

        Log.v(TAG, "KeychainUnlock action: " + action);

        if (action.equals(AVAILABLE)) {
                    sendAvailabilityResult();
                    return true;
        } else if (action.equals(HAS)) {
                    final String key = args.getString(0);

                    SharedPreferences sharedPref = cordova.getActivity().getApplicationContext().getSharedPreferences(SHARED_PREFS_NAME,Context.MODE_PRIVATE);
                    String enc = sharedPref.getString("fing" + key, "");

                    if (!enc.equals("")) {
                        mPluginResult = new PluginResult(PluginResult.Status.OK);
                    } else {
                        mPluginResult = new PluginResult(PluginResult.Status.ERROR);
                    }

                    mCallbackContext.sendPluginResult(mPluginResult);
                    return true;
        } else if (action.equals(SAVE)) {
                     final String key = args.getString(0);
                     final String password = args.getString(1);
                     //boolean setUserAuthenticationRequired = false; // args.get(2).equals(null) || args.getBoolean(2);
                     SecretKey secretKey = getSecretKey();
    
                    if (secretKey == null) {
                        if (createKey(false)) {
                            secretKey = getSecretKey();
                        }
                    }
                    mKeyID = key;
                    mToEncrypt = password;

                    SharedPreferences sharedPref = cordova.getActivity().getApplicationContext().getSharedPreferences(SHARED_PREFS_NAME,Context.MODE_PRIVATE);
                    SharedPreferences.Editor editor = sharedPref.edit();

                    if (initCipher(Cipher.ENCRYPT_MODE, cordova)) {
                        byte[] enc = new byte[0];
                        try {
                            enc = mCipher.doFinal(mToEncrypt.getBytes());
                            editor.putString("fing" + mKeyID, Base64.encodeToString(enc, Base64.DEFAULT));
                            editor.putString("fing_iv" + mKeyID, Base64.encodeToString(mCipher.getIV(), Base64.DEFAULT));
                            editor.apply();
                            mPluginResult = new PluginResult(PluginResult.Status.OK);
                        } catch (IllegalBlockSizeException e) {
                            mPluginResult = new PluginResult(PluginResult.Status.ERROR, "Error string is to big.");
                        } catch (BadPaddingException e) {
                            mPluginResult = new PluginResult(PluginResult.Status.ERROR, "Error Bad Padding.");
                        }
                    } else {
                        mPluginResult = new PluginResult(PluginResult.Status.ERROR, "Error init Cipher.");
                    }
                    mCallbackContext.sendPluginResult(mPluginResult);
                    return true;
        } else if (action.equals(VERIFY)) {
            final String key = args.getString(0);
            final String message = args.getString(1);

                    SecretKey secretKey = getSecretKey();
                    if (secretKey == null) {
                        if (createKey(false)) {
                            secretKey = getSecretKey();
                        }
                    }

                    mKeyID = key;

                    if (secretKey == null) {
                        mPluginResult = new PluginResult(PluginResult.Status.ERROR, "No Secret Key.");
                        mCallbackContext.sendPluginResult(mPluginResult);
                    } else {
                        mPluginResult.setKeepCallback(true);
                        if (!initCipher(Cipher.DECRYPT_MODE, cordova)) {
                            // ERROR
                        }
                        onAuthenticated();
                    }
             return true;
        } else if (action.equals(DELETE)) {
            final String key = args.getString(0);

            SharedPreferences sharedPref = cordova.getActivity().getApplicationContext().getSharedPreferences(SHARED_PREFS_NAME,Context.MODE_PRIVATE);
            SharedPreferences.Editor editor = sharedPref.edit();

            editor.remove("fing" + key);
            editor.remove("fing_iv" + key);
            boolean removed = editor.commit();

            if (removed) {
                mPluginResult = new PluginResult(PluginResult.Status.OK);
            } else {
                mPluginResult = new PluginResult(PluginResult.Status.ERROR);
            }
            mCallbackContext.sendPluginResult(mPluginResult);
            return true;
        } else if (action.equals(UPDATE)) {
            String key = args.getString(0);
            String oldActivityPackageName = args.getString(1);
            //Get old shared Preferences e.g: "com.outsystems.android.WebApplicationActivity"
            SharedPreferences oldSharedPref = cordova.getActivity().getApplicationContext().getSharedPreferences(oldActivityPackageName,Context.MODE_PRIVATE);
            String enc = oldSharedPref.getString("fing" + key, "");
            
            if (!enc.equals("")) {
                SharedPreferences newSharedPref = cordova.getActivity().getApplicationContext().getSharedPreferences(SHARED_PREFS_NAME,Context.MODE_PRIVATE);
                SharedPreferences.Editor newEditor = newSharedPref.edit();
                newEditor.putString("fing" + key, oldSharedPref.getString("fing" + key, ""));
                newEditor.putString("fing_iv" + key, oldSharedPref.getString("fing_iv" + key, ""));
                newEditor.commit();
                
                SharedPreferences.Editor oldEditor = oldSharedPref.edit();
                oldEditor.remove("fing" + key);
                oldEditor.remove("fing_iv" + key);
                oldEditor.commit();
            }
            
            mPluginResult = new PluginResult(PluginResult.Status.OK);
            mCallbackContext.sendPluginResult(mPluginResult);
            return true;
        }
        return false;
    }

    private void sendAvailabilityResult() {
        mPluginResult = new PluginResult(PluginResult.Status.OK);
        mCallbackContext.sendPluginResult(mPluginResult);
    }

    /**
     * Initialize the {@link Cipher} instance with the created key in the {@link #createKey()}
     * method.
     *
     * @return {@code true} if initialization is successful, {@code false} if the lock screen has
     * been disabled or reset after the key was generated, or if a fingerprint got enrolled after
     * the key was generated.
     */
    private boolean initCipher(int mode, CordovaInterface cordova) {
        boolean initCipher = false;
        String errorMessage = "";
        String initCipherExceptionErrorPrefix = "Failed to init Cipher: ";
        try {
            SecretKey key = getSecretKey();
            if (key == null) {
                if (createKey(false)) {
                    key = getSecretKey();
                }
            }

            if (mode == Cipher.ENCRYPT_MODE) {
                SecureRandom r = new SecureRandom();
                byte[] ivBytes = new byte[16];
                r.nextBytes(ivBytes);
                mCipher.init(mode, key);
            } else {
                SharedPreferences sharedPref = cordova.getActivity().getApplicationContext().getSharedPreferences(SHARED_PREFS_NAME,Context.MODE_PRIVATE);
                byte[] ivBytes = Base64.decode(sharedPref.getString("fing_iv" + mKeyID, ""), Base64.NO_WRAP);
                mCipher.init(mode, key, new IvParameterSpec(ivBytes));
            }
            initCipher = true;
        } catch (KeyPermanentlyInvalidatedException e) {
            removePermanentlyInvalidatedKey();
            errorMessage = "KeyPermanentlyInvalidatedException";
            setPluginResultError(errorMessage);
        } catch (InvalidKeyException e) {
            errorMessage = initCipherExceptionErrorPrefix + "InvalidKeyException";
        } catch (InvalidAlgorithmParameterException e) {
            errorMessage = initCipherExceptionErrorPrefix + "InvalidAlgorithmParameterException";
            e.printStackTrace();
        }
        if (!initCipher) {
            Log.e(TAG, errorMessage);
        }
        return initCipher;
    }

    private static SecretKey getSecretKey() {
        String errorMessage = "";
        String getSecretKeyExceptionErrorPrefix = "Failed to get SecretKey from KeyStore: ";
        SecretKey key = null;
        try {
            mKeyStore.load(null);
            key = (SecretKey) mKeyStore.getKey(CLIENT_ID, null);
        } catch (KeyStoreException e) {
            errorMessage = getSecretKeyExceptionErrorPrefix + "KeyStoreException: " + e.toString();
        } catch (CertificateException e) {
            errorMessage = getSecretKeyExceptionErrorPrefix + "CertificateException: " + e.toString();
        } catch (UnrecoverableKeyException e) {
            errorMessage = getSecretKeyExceptionErrorPrefix + "UnrecoverableKeyException: " + e.toString();
        } catch (IOException e) {
            errorMessage = getSecretKeyExceptionErrorPrefix + "IOException: " + e.toString();
        } catch (NoSuchAlgorithmException e) {
            errorMessage = getSecretKeyExceptionErrorPrefix + "NoSuchAlgorithmException: " + e.toString();
        }
        if (key == null) {
            Log.e(TAG, errorMessage);
        }
        return key;
    }

    /**
     * Creates a symmetric key in the Android Key Store which can only be used after the user has
     * authenticated with fingerprint.
     */
    public static boolean createKey(final boolean setUserAuthenticationRequired) {
        String errorMessage = "";
        String createKeyExceptionErrorPrefix = "Failed to create key: ";
        boolean isKeyCreated = false;
        // The enrolling flow for fingerprint. This is where you ask the user to set up fingerprint
        // for your flow. Use of keys is necessary if you need to know if the set of
        // enrolled fingerprints has changed.
        try {
            mKeyStore.load(null);
            // Set the alias of the entry in Android KeyStore where the key will appear
            // and the constrains (purposes) in the constructor of the Builder
            mKeyGenerator.init(new KeyGenParameterSpec.Builder(CLIENT_ID,
                    KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                    .setUserAuthenticationRequired(setUserAuthenticationRequired)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                    .build());
            mKeyGenerator.generateKey();
            isKeyCreated = true;
        } catch (NoSuchAlgorithmException e) {
            Log.e(TAG, createKeyExceptionErrorPrefix + "NoSuchAlgorithmException: " + e.toString());
            errorMessage = PluginError.NO_SUCH_ALGORITHM_EXCEPTION.name();
        } catch (InvalidAlgorithmParameterException e) {
            Log.e(TAG, createKeyExceptionErrorPrefix + "InvalidAlgorithmParameterException: " + e.toString());
            errorMessage = PluginError.INVALID_ALGORITHM_PARAMETER_EXCEPTION.name();
        } catch (CertificateException e) {
            Log.e(TAG, createKeyExceptionErrorPrefix + "CertificateException: " + e.toString());
            errorMessage = PluginError.CERTIFICATE_EXCEPTION.name();
        } catch (IOException e) {
            Log.e(TAG, createKeyExceptionErrorPrefix + "IOException: " + e.toString());
            errorMessage = PluginError.IO_EXCEPTION.name();
        }
        if (!isKeyCreated) {
            Log.e(TAG, errorMessage);
            setPluginResultError(errorMessage);
        }
        return isKeyCreated;
    }

    public static void onAuthenticated() {
        String result = "";
        String errorMessage = "";

        try {
                SharedPreferences sharedPref = mContext.getSharedPreferences(SHARED_PREFS_NAME,Context.MODE_PRIVATE);
                byte[] enc = Base64.decode(sharedPref.getString("fing" + mKeyID, ""), Base64.DEFAULT);
                byte[] decrypted = mCipher.doFinal(enc);
                result = new String(decrypted);
        } catch (BadPaddingException e) {
            errorMessage = "Failed to encrypt the data with the generated key: BadPaddingException: " + e.getMessage();
            Log.e(TAG, errorMessage);
        } catch (IllegalBlockSizeException e) {
            errorMessage = "Failed to encrypt the data with the generated key: IllegalBlockSizeException: " + e.getMessage();
            Log.e(TAG, errorMessage);
        } catch (IllegalStateException e) {
            errorMessage = "Failed to decrypt the data with the generated key: IllegalStateException: " + e.getMessage();
        }

        if (!result.equals("")) {
            mPluginResult = new PluginResult(PluginResult.Status.OK, result);
            mPluginResult.setKeepCallback(false);
        } else {
            mPluginResult = new PluginResult(PluginResult.Status.ERROR, errorMessage);
            mPluginResult.setKeepCallback(false);
        }
        mCallbackContext.sendPluginResult(mPluginResult);
    }

    public static boolean setPluginResultError(String errorMessage) {
        mCallbackContext.error(errorMessage);
        mPluginResult = new PluginResult(PluginResult.Status.ERROR);
        return false;
    }

    /**
     * Get a String preference
     *
     * @param context App context
     * @param name    Preference name
     * @param key     Preference key
     * @return Requested preference, if not exist returns null
     */
    public static String getStringPreference(Context context, String name, String key) {
        SharedPreferences sharedPreferences = context.getSharedPreferences(name, Context.MODE_PRIVATE);
        return sharedPreferences.getString(key, null);
    }

    /**
     * Set a String preference
     *
     * @param context App context
     * @param name    Preference name
     * @param key     Preference key
     * @param value   Preference value to be saved
     */
    public static void setStringPreference(Context context, String name, String key, String value) {
        SharedPreferences sharedPreferences = context.getSharedPreferences(name, Context.MODE_PRIVATE);
        SharedPreferences.Editor editor = sharedPreferences.edit();

        editor.putString(key, value);
        editor.apply();
    }

    /**
     * Delete a String preference
     *
     * @param context App context
     * @param name    Preference name
     * @param key     Preference key
     * @return Returns true if deleted otherwise false
     */
    public static boolean deleteStringPreference(Context context, String name, String key) {
        SharedPreferences sharedPreferences = context.getSharedPreferences(name, Context.MODE_PRIVATE);
        SharedPreferences.Editor editor = sharedPreferences.edit();

        return editor.remove(key).commit();
    }

    private void removePermanentlyInvalidatedKey() {
        try {
            mKeyStore.deleteEntry(CLIENT_ID);
            Log.i(TAG, "Permanently invalidated key was removed.");
        } catch (KeyStoreException e) {
            Log.e(TAG, e.getMessage());
        }
    }
}
