package by.chemerisuk.cordova.firebase;

import android.util.Log;

import by.chemerisuk.cordova.support.CordovaMethod;
import by.chemerisuk.cordova.support.ReflectiveCordovaPlugin;

import com.google.android.gms.tasks.OnCompleteListener;
import com.google.android.gms.tasks.Task;
import com.google.firebase.FirebaseApiNotAvailableException;
import com.google.firebase.FirebaseTooManyRequestsException;
import com.google.firebase.auth.AuthCredential;
import com.google.firebase.auth.FacebookAuthProvider;
import com.google.firebase.auth.FirebaseAuth;
import com.google.firebase.auth.FirebaseAuthException;
import com.google.firebase.auth.FirebaseAuthInvalidCredentialsException;
import com.google.firebase.auth.FirebaseUser;
import com.google.firebase.auth.FirebaseAuth.AuthStateListener;
import com.google.firebase.auth.GetTokenResult;
import com.google.firebase.auth.GoogleAuthProvider;
import com.google.firebase.auth.PhoneAuthCredential;
import com.google.firebase.auth.PhoneAuthProvider;
import com.google.firebase.auth.TwitterAuthProvider;
import com.google.firebase.FirebaseException;
import com.google.gson.Gson;
import com.google.gson.JsonObject;

import org.apache.cordova.CallbackContext;
import org.apache.cordova.PluginResult;

import org.json.JSONException;
import org.json.JSONObject;

import static java.util.concurrent.TimeUnit.MILLISECONDS;


public class FirebaseAuthenticationPlugin extends ReflectiveCordovaPlugin implements AuthStateListener {
    //region constants
    private static final String TAG = "FirebaseAuthentication";
    //endregion

    //region fields
    private FirebaseAuth firebaseAuth;
    private PhoneAuthProvider phoneAuthProvider;
    private CallbackContext authStateCallback;
    //endregion

    //region initialization
    @Override
    protected void pluginInitialize() {
        Log.d(TAG, "Starting Firebase Authentication plugin");

        this.firebaseAuth = FirebaseAuth.getInstance();
        this.phoneAuthProvider = PhoneAuthProvider.getInstance();
    }
    //endregion

    //region state-listeners
    @CordovaMethod
    private void setAuthStateChanged(boolean disable, CallbackContext callbackContext) {
        if (this.authStateCallback != null) {
            this.authStateCallback = null;
            this.firebaseAuth.removeAuthStateListener(this);
        }

        if (!disable) {
            this.authStateCallback = callbackContext;
            this.firebaseAuth.addAuthStateListener(this);
        }
    }

    @Override
    public void onAuthStateChanged(FirebaseAuth auth) {
        if (this.authStateCallback != null) {
            PluginResult pluginResult = getProfileResult(this.firebaseAuth.getCurrentUser());
            pluginResult.setKeepCallback(true);
            this.authStateCallback.sendPluginResult(pluginResult);
        }
    }
    //endregion

    //region state-getters
    @CordovaMethod
    private void getCurrentUser(CallbackContext callbackContext) {
        PluginResult pluginResult = getProfileResult(this.firebaseAuth.getCurrentUser());
        callbackContext.sendPluginResult(pluginResult);
    }

    @CordovaMethod
    private void getIdToken(boolean forceRefresh, final CallbackContext callbackContext) {
        FirebaseUser user = this.firebaseAuth.getCurrentUser();

        if (user == null) {
            callbackContext.success("User is not authorized");
        } else {
            user.getIdToken(forceRefresh)
                .addOnCompleteListener(cordova.getActivity(), task -> {
                    if (task.isSuccessful()) {
                        callbackContext.success(task.getResult().getToken());
                    } else {
                        callbackContext.error(task.getException().getMessage());
                    }
                });
        }
    }

    //endregion

    //region state-setters
    @CordovaMethod
    private void setLanguageCode(String languageCode, CallbackContext callbackContext) {
        if (languageCode == null) {
            this.firebaseAuth.useAppLanguage();
        } else {
            this.firebaseAuth.setLanguageCode(languageCode);
        }

        callbackContext.success();
    }

    @CordovaMethod
    private void signOut(CallbackContext callbackContext) {
        this.firebaseAuth.signOut();

        callbackContext.success();
    }
    //endregion

    //region email-login
    @CordovaMethod
    private void createUserWithEmailAndPassword(String email, String password, CallbackContext callbackContext) {
        this.firebaseAuth.createUserWithEmailAndPassword(email, password)
            .addOnCompleteListener(cordova.getActivity(), createCompleteListener(callbackContext));
    }

    @CordovaMethod
    private void sendEmailVerification(CallbackContext callbackContext) {
        FirebaseUser user = this.firebaseAuth.getCurrentUser();

        if (user == null) {
            callbackContext.error("User is not authorized");
        } else {
            user.sendEmailVerification()
                .addOnCompleteListener(cordova.getActivity(), createCompleteListener(callbackContext));
        }
    }

    @CordovaMethod
    private void sendPasswordResetEmail(String email, CallbackContext callbackContext) {
        this.firebaseAuth.sendPasswordResetEmail(email)
            .addOnCompleteListener(cordova.getActivity(), createCompleteListener(callbackContext));
    }

    @CordovaMethod
    private void signInWithEmailAndPassword(String email, String password, CallbackContext callbackContext) {
        this.firebaseAuth.signInWithEmailAndPassword(email, password)
            .addOnCompleteListener(cordova.getActivity(), createCompleteListener(callbackContext));
    }
    //endregion

    //region anon-login
    @CordovaMethod
    private void signInAnonymously(final CallbackContext callbackContext) {
        this.firebaseAuth.signInAnonymously()
            .addOnCompleteListener(cordova.getActivity(), createCompleteListener(callbackContext));
    }
    //endregion

    //region external-login
    @CordovaMethod
    private void signInWithGoogle(String idToken, String accessToken, CallbackContext callbackContext) {
        signInWithCredential(GoogleAuthProvider.getCredential(idToken, accessToken), callbackContext);
    }

    @CordovaMethod
    private void signInWithFacebook(String accessToken, CallbackContext callbackContext) {
        signInWithCredential(FacebookAuthProvider.getCredential(accessToken), callbackContext);
    }

    @CordovaMethod
    private void signInWithTwitter(String token, String secret, CallbackContext callbackContext) {
        signInWithCredential(TwitterAuthProvider.getCredential(token, secret), callbackContext);
    }

    @CordovaMethod
    private void signInWithCustomToken(String idToken, CallbackContext callbackContext) {
        this.firebaseAuth.signInWithCustomToken(idToken)
            .addOnCompleteListener(cordova.getActivity(), createCompleteListener(callbackContext));
    }

    private void signInWithCredential(AuthCredential credential, CallbackContext callbackContext) {
        this.firebaseAuth.signInWithCredential(credential)
            .addOnCompleteListener(cordova.getActivity(), createCompleteListener(callbackContext));
    }
    //endregion

    //region otp-login

    @CordovaMethod
    private void signInWithVerificationId(String verificationId, String code, CallbackContext callbackContext) {
        signInWithPhoneCredential(PhoneAuthProvider.getCredential(verificationId, code))
            .addOnCompleteListener(cordova.getActivity(), createCompleteListener(callbackContext));
    }

    @CordovaMethod
    private void verifyPhoneNumber(String phoneNumber, long timeoutMillis, final CallbackContext callbackContext) {
        phoneAuthProvider.verifyPhoneNumber(phoneNumber, timeoutMillis, MILLISECONDS, cordova.getActivity(),
            new PhoneAuthProvider.OnVerificationStateChangedCallbacks() {
                @Override
                public void onVerificationCompleted(PhoneAuthCredential credential) {
                    signInWithPhoneCredential(credential)
                        .addOnCompleteListener(cordova.getActivity(), createOTPVerificationListener(callbackContext));
                }

                @Override
                public void onCodeSent(String verificationId, PhoneAuthProvider.ForceResendingToken forceResendingToken) {
                    try {
                        callbackContext.success(new OTPResult(null,verificationId).toJson());
                    } catch (JSONException e) {
                        callbackContext.error(e.getMessage());
                    }
                }

                @Override
                public void onVerificationFailed(FirebaseException e) {
                    callbackContext.error(e.getMessage());
                }
            }
        );
    }

    private Task<OTPResult> signInWithPhoneCredential(PhoneAuthCredential credential) {
        FirebaseUser user = this.firebaseAuth.getCurrentUser();
        if (user != null) {
            return user.updatePhoneNumber(credential)
                .continueWithTask(task -> user.getIdToken(false)
                    .continueWith(tokenResult -> new OTPResult(tokenResult.getResult().getToken(), null)));
        } else {
            return this.firebaseAuth.signInWithCredential(credential)
                .continueWithTask(task -> task.getResult().getUser().getIdToken(false)
                    .continueWith(tokenResult -> new OTPResult(tokenResult.getResult().getToken(), null)));
        }
    }

    private static <T> OnCompleteListener<T> createOTPVerificationListener(final CallbackContext callbackContext) {
        return task -> {
            if (task.isSuccessful()) {
                Object result = task.getResult();
                if (result instanceof OTPResult) {
                    try {
                        callbackContext.success(((OTPResult) result).toJson());
                    } catch (JSONException e) {
                        callbackContext.error(e.getMessage());
                    }
                }
                callbackContext.success();
            } else {
                Exception e = task.getException();
                Log.e("FirebaseOTP", "Failed on verify phone number", e);

                String errorCode = e.getMessage();
                if (e instanceof FirebaseAuthInvalidCredentialsException) {
                    errorCode = "invalidCredential";
                } else if (e instanceof FirebaseAuthException) {
                    errorCode = "firebaseAuth";
                } else if (e instanceof FirebaseTooManyRequestsException) {
                    errorCode = "quotaExceeded";
                } else if (e instanceof FirebaseApiNotAvailableException) {
                    errorCode = "apiNotAvailable";
                }
                callbackContext.error(errorCode);
            }
        };
    }

    //endregion

    //region private-methods
    private static <T> OnCompleteListener<T> createCompleteListener(final CallbackContext callbackContext) {
        return task -> {
            if (task.isSuccessful()) {
                callbackContext.success();
            } else {
                callbackContext.error(task.getException().getMessage());
            }
        };
    }

    private static PluginResult getProfileResult(FirebaseUser user) {
        if (user == null) {
            return new PluginResult(PluginResult.Status.OK, (String) null);
        }

        JSONObject result = new JSONObject();

        try {
            result.put("uid", user.getUid());
            result.put("displayName", user.getDisplayName());
            result.put("email", user.getEmail());
            result.put("phoneNumber", user.getPhoneNumber());
            result.put("photoURL", user.getPhotoUrl());
            result.put("providerId", user.getProviderId());
            result.put("emailVerified", user.isEmailVerified());

            return new PluginResult(PluginResult.Status.OK, result);
        } catch (JSONException e) {
            Log.e(TAG, "Fail to process getProfileData", e);

            return new PluginResult(PluginResult.Status.ERROR, e.getMessage());
        }
    }
    //endregion
}
