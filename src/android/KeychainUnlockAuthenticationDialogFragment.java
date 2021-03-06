/*
 * Copyright (C) 2015 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License
 */

package ar.com.tecnologica.KeychainUnlock;

import android.app.DialogFragment;
import android.app.KeyguardManager;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.SharedPreferences;
import android.hardware.fingerprint.FingerprintManager;
import android.os.Bundle;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.inputmethod.InputMethodManager;
import android.widget.Button;
import android.widget.ImageView;
import android.widget.TextView;
import android.widget.Toast;

/**
 * A dialog which uses fingerprint APIs to authenticate the user, and falls back to password
 * authentication if fingerprint is not available.
 */
public class KeychainUnlockAuthenticationDialogFragment extends DialogFragment implements KeychainUnlockUiHelper.Callback {

    private static final String TAG = "KeychainUnlockDialog";
    private static final int REQUEST_CODE_CONFIRM_DEVICE_CREDENTIALS = 1;

    private Button mCancelButton;
    private Button mSecondDialogButton;
    private View mKeychainUnlockContent;

    private Stage mStage = Stage.FINGERPRINT;

    private KeyguardManager mKeyguardManager;
    private FingerprintManager.CryptoObject mCryptoObject;
    private KeychainUnlockUiHelper mKeychainUnlockUiHelper;
    //private KeychainUnlockAux mKeychainUnlock;
    KeychainUnlockUiHelper.KeychainUnlockUiHelperBuilder mKeychainUnlockUiHelperBuilder;

    public KeychainUnlockAuthenticationDialogFragment() {
    }

    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        // Do not create a new Fragment when the Activity is re-created such as orientation changes.
        setRetainInstance(true);
        setStyle(DialogFragment.STYLE_NO_TITLE, android.R.style.Theme_Material_Light_Dialog);

        mKeyguardManager = (KeyguardManager) getContext().getSystemService(Context.KEYGUARD_SERVICE);
        mKeychainUnlockUiHelperBuilder = new KeychainUnlockUiHelper.KeychainUnlockUiHelperBuilder(getContext(), getContext().getSystemService(FingerprintManager.class));
    }

    @Override
    public View onCreateView(LayoutInflater inflater, ViewGroup container, Bundle savedInstanceState) {
        Bundle args = getArguments();
        // Inflate layout
        int fingerprint_dialog_container_id = getResources().getIdentifier("fingerprint_dialog_container", "layout", KeychainUnlock.packageName);
        View v = inflater.inflate(fingerprint_dialog_container_id, container, false);

        // Set dialog Title
        int fingerprint_auth_dialog_title_id = getResources().getIdentifier("fingerprint_auth_dialog_title", "id", KeychainUnlock.packageName);
        TextView dialogTitleTextView = (TextView) v.findViewById(fingerprint_auth_dialog_title_id);
        if (null != KeychainUnlock.mDialogTitle) {
            dialogTitleTextView.setText(KeychainUnlock.mDialogTitle);
        }

        // Set dialog message
        int fingerprint_description_id = getResources().getIdentifier("fingerprint_description", "id", KeychainUnlock.packageName);
        TextView dialogMessageTextView = (TextView) v.findViewById(fingerprint_description_id);
        if (null != KeychainUnlock.mDialogMessage) {
            dialogMessageTextView.setText(KeychainUnlock.mDialogMessage);
        }

        // Set dialog hing
        int fingerprint_hint_id = getResources().getIdentifier("fingerprint_status", "id", KeychainUnlock.packageName);
        TextView dialogHintTextView = (TextView) v.findViewById(fingerprint_hint_id);
        if (null != KeychainUnlock.mDialogHint) {
            dialogHintTextView.setText(KeychainUnlock.mDialogHint);
        }

        int cancel_button_id = getResources().getIdentifier("cancel_button", "id", KeychainUnlock.packageName);
        mCancelButton = (Button) v.findViewById(cancel_button_id);
        mCancelButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                KeychainUnlock.onCancelled();
                dismissAllowingStateLoss();
            }
        });

        int second_dialog_button_id = getResources().getIdentifier("second_dialog_button", "id", KeychainUnlock.packageName);
        mSecondDialogButton = (Button) v.findViewById(second_dialog_button_id);
        //mSecondDialogButton.setVisibility(View.GONE); // XXX
        mSecondDialogButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                goToBackup();
            }
        });
        int fingerprint_container_id = getResources().getIdentifier("fingerprint_container", "id", KeychainUnlock.packageName);
        mKeychainUnlockContent = v.findViewById(fingerprint_container_id);

        int new_fingerprint_enrolled_description_id = getResources().getIdentifier("new_fingerprint_enrolled_description", "id", KeychainUnlock.packageName);

        int fingerprint_icon_id = getResources().getIdentifier("fingerprint_icon", "id", KeychainUnlock.packageName);
        int fingerprint_status_id = getResources().getIdentifier("fingerprint_status", "id", KeychainUnlock.packageName);
        mKeychainUnlockUiHelper = mKeychainUnlockUiHelperBuilder.build((ImageView) v.findViewById(fingerprint_icon_id),
                (TextView) v.findViewById(fingerprint_status_id), this);
        updateStage();

        // If fingerprint authentication is not available, switch immediately to the backup
        // (password) screen.
        if (!mKeychainUnlockUiHelper.isKeychainUnlockAvailable()) {
            goToBackup();
        }
        return v;
    }


    @Override
    public void onResume() {
        super.onResume();
        if (mStage == Stage.FINGERPRINT) {
            mKeychainUnlockUiHelper.startListening(mCryptoObject);
        }
    }

    public void setStage(Stage stage) {
        mStage = stage;
    }

    @Override
    public void onPause() {
        super.onPause();
        mKeychainUnlockUiHelper.stopListening();
    }

    /**
     * Sets the crypto object to be passed in when authenticating with fingerprint.
     */
    public void setCryptoObject(FingerprintManager.CryptoObject cryptoObject) {
        mCryptoObject = cryptoObject;
    }

    /**
     * Switches to backup (password) screen. This either can happen when fingerprint is not
     * available or the user chooses to use the password authentication method by pressing the
     * button. This can also happen when the user had too many fingerprint attempts.
     */
    private void goToBackup() {
        mStage = Stage.BACKUP;
        updateStage();
    }

    private void updateStage() {
        int cancel_id = getResources().getIdentifier("cancel", "string", KeychainUnlock.packageName);
        switch (mStage) {
            case FINGERPRINT:
                mCancelButton.setText(cancel_id);
                int use_backup_id = getResources().getIdentifier("use_backup", "string", KeychainUnlock.packageName);
                mSecondDialogButton.setText(use_backup_id);
                mKeychainUnlockContent.setVisibility(View.VISIBLE);
                break;
            case NEW_FINGERPRINT_ENROLLED:
                // Intentional fall through
            case BACKUP:
                if (mStage == Stage.NEW_FINGERPRINT_ENROLLED) {
                    // XXX
                }
                if (!mKeyguardManager.isKeyguardSecure()) {
                    // Show a message that the user hasn't set up a lock screen.
                    int secure_lock_screen_required_id = getResources().getIdentifier("secure_lock_screen_required", "string",
                                    KeychainUnlock.packageName);
                    Toast.makeText(getContext(), getString(secure_lock_screen_required_id), Toast.LENGTH_LONG).show();
                    return;
                }
                showAuthenticationScreen();
                break;
        }
    }

    private void showAuthenticationScreen() {
        // Create the Confirm Credentials screen. You can customize the title and description. Or
        // we will provide a generic one for you if you leave it null
        Intent intent = mKeyguardManager.createConfirmDeviceCredentialIntent(null, null);
        if (intent != null) {
            startActivityForResult(intent, REQUEST_CODE_CONFIRM_DEVICE_CREDENTIALS);
        }
    }

    @Override
    public void onActivityResult(int requestCode, int resultCode, Intent data) {
        if (requestCode == REQUEST_CODE_CONFIRM_DEVICE_CREDENTIALS) {
            // Challenge completed, proceed with using cipher
            if (resultCode == getActivity().RESULT_OK) {
                //KeychainUnlock.onAuthenticated(false /* used backup */, null);
                KeychainUnlock.onAuthenticated();
            } else {
                // The user canceled or didn’t complete the lock screen
                // operation. Go to error/cancellation flow.
                KeychainUnlock.onCancelled();
            }
            dismissAllowingStateLoss();
        }
    }

    @Override
    //public void onAuthenticated(FingerprintManager.AuthenticationResult result) {
    public void onAuthenticated() {
        // Callback from KeychainUnlockUiHelper. Let the activity know that authentication was
        // successful.
        //KeychainUnlock.onAuthenticated(true /* withKeychainUnlock */, result);
        KeychainUnlock.onAuthenticated();
        dismissAllowingStateLoss();
    }

    @Override
    public void onError(CharSequence errString) {
        if (getActivity() != null && isAdded()) {
                goToBackup();
        }
    }

    @Override
    public void onCancel(DialogInterface dialog) {
        super.onCancel(dialog);
        KeychainUnlock.onCancelled();
    }

    /**
     * Enumeration to indicate which authentication method the user is trying to authenticate with.
     */
    public enum Stage {
        FINGERPRINT,
        NEW_FINGERPRINT_ENROLLED,
        BACKUP
    }
}
