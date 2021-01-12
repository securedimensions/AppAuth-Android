/*
 * Copyright 2015 The AppAuth for Android Authors. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the
 * License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing permissions and
 * limitations under the License.
 */

package net.openid.appauthdemo;

import android.annotation.TargetApi;
import android.app.PendingIntent;
import android.content.Intent;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.Editable;
import android.text.TextUtils;
import android.text.TextWatcher;
import android.util.Log;
import android.view.View;
import android.widget.AdapterView;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.ImageView;
import android.widget.Spinner;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.ColorRes;
import androidx.annotation.MainThread;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.annotation.WorkerThread;
import androidx.appcompat.app.AppCompatActivity;
import androidx.browser.customtabs.CustomTabsIntent;

import com.google.android.material.snackbar.Snackbar;

import net.openid.appauth.AppAuthConfiguration;
import net.openid.appauth.AuthState;
import net.openid.appauth.AuthorizationException;
import net.openid.appauth.AuthorizationRequest;
import net.openid.appauth.AuthorizationService;
import net.openid.appauth.AuthorizationServiceDiscovery;
import net.openid.appauth.ResponseTypeValues;
import net.openid.appauth.browser.AnyBrowserMatcher;
import net.openid.appauth.browser.BrowserMatcher;
import net.openid.appauth.browser.CustomTabManager;
import net.openid.appauth.browser.ExactBrowserMatcher;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.nio.charset.Charset;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import okio.Okio;


/**
 * Displays the authorized state of the user. This activity demonstrate the options for
 * disposing the current state or logging out.
 * For Mobile Apps that leverage an OpenID Connect Operator for login, that flow is executed
 * in a Browser; either WebView or external system Browser.
 * To logout the user, two options exist:
 * (i) Clear the current state and delete access_token and refresh_token. But that leaves the user
 * logged in with the external Browser.
 * (ii) Logout via the Browser visiting the OP and the IdP originally used for login. If this flow
 * completes, the user is redirected back to the application.
 */
public class LogoutActivity extends AppCompatActivity {
    private static final String TAG = "LogoutActivity";

    private AuthorizationService mAuthService;
    private AuthStateManager mStateManager;
    private final AtomicReference<Uri> mLogoutRequest = new AtomicReference<>();
    private final AtomicReference<CustomTabsIntent> mLogoutIntent = new AtomicReference<>();

    private ExecutorService mExecutor;
    private Configuration mConfiguration;
    private CountDownLatch mLogoutIntentLatch = new CountDownLatch(1);

    private boolean mUsePendingIntents;
    private static final int RC_AUTH = 101;

    @NonNull
    private BrowserMatcher mBrowserMatcher = AnyBrowserMatcher.INSTANCE;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        mStateManager = AuthStateManager.getInstance(this);
        mExecutor = Executors.newSingleThreadExecutor();
        mConfiguration = Configuration.getInstance(this);

        if (!mStateManager.getCurrent().isAuthorized()) {
            Log.i(TAG, "User is not authenticated, proceeding to login activity");
            startActivity(new Intent(this, LoginActivity.class));
            finish();
            return;
        }

        Configuration config = Configuration.getInstance(this);
        if (config.hasConfigurationChanged()) {
            Toast.makeText(
                this,
                "Configuration change detected",
                Toast.LENGTH_SHORT)
                .show();
            clearState();
            return;
        }

        setContentView(R.layout.activity_logout);

        recreateAuthorizationService();

        configureBrowserSelector();
        if (mConfiguration.hasConfigurationChanged()) {
            // discard any existing authorization state due to the change of configuration
            Log.i(TAG, "Configuration change detected, discarding old state");
            mStateManager.replace(new AuthState());
            mConfiguration.acceptConfiguration();
        }

        ((EditText)findViewById(R.id.logout_state_value)).addTextChangedListener(
            new LogoutActivity.LogoutStateChangeHandler());

        displayLoading("Initializing Logout Request...");
        mExecutor.submit(this::initializeLogoutRequest);

    }

    @Override
    protected void onStart() {
        super.onStart();

        if (mExecutor.isShutdown()) {
            mExecutor = Executors.newSingleThreadExecutor();
        }

        if (mStateManager.getCurrent().isAuthorized()) {
            displayAuthorized();
            return;
        }

    }

    @Override
    protected void onSaveInstanceState(Bundle state) {
        super.onSaveInstanceState(state);
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        if (mAuthService != null) {
            mAuthService.dispose();
        }
        mExecutor.shutdownNow();
    }

    @MainThread
    private void displayLoading(String message) {
        findViewById(R.id.loading_container).setVisibility(View.VISIBLE);
        findViewById(R.id.authorized).setVisibility(View.GONE);

        ((TextView)findViewById(R.id.loading_description)).setText(message);
    }

    @MainThread
    private void displayAuthorized() {
        findViewById(R.id.authorized).setVisibility(View.VISIBLE);
        findViewById(R.id.loading_container).setVisibility(View.GONE);

        AuthState state = mStateManager.getCurrent();

        Button clearStateButton = (Button) findViewById(R.id.clear_state);
        clearStateButton.setVisibility(View.VISIBLE);
        clearStateButton.setOnClickListener((View view) -> clearState());

        Button logOutButton = (Button) findViewById(R.id.log_out);
        logOutButton.setVisibility(View.VISIBLE);
        logOutButton.setOnClickListener((View view) -> doLogout());

    }

    @MainThread
    private void showSnackbar(String message) {
        Snackbar.make(findViewById(R.id.coordinator),
            message,
            Snackbar.LENGTH_SHORT)
            .show();
    }

    @MainThread
    private void clearState() {
        // discard the authorization and token state, but retain the configuration and
        // dynamic client registration (if applicable), to save from retrieving them again.
        AuthState currentState = mStateManager.getCurrent();
        AuthState clearedState =
            new AuthState(currentState.getAuthorizationServiceConfiguration());
        if (currentState.getLastRegistrationResponse() != null) {
            clearedState.update(currentState.getLastRegistrationResponse());
        }
        mStateManager.replace(clearedState);

        Intent mainIntent = new Intent(this, LoginActivity.class);
        mainIntent.setFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP);
        startActivity(mainIntent);
        finish();
    }

    @MainThread
    void doLogout() {
        displayLoading("Starting logout");

        try {
            mLogoutIntentLatch.await();
        } catch (InterruptedException ex) {
            Log.w(TAG, "Interrupted while waiting for auth intent");
        }

        AuthState currentState = mStateManager.getCurrent();
        AuthState clearedState =
            new AuthState(currentState.getAuthorizationServiceConfiguration());
        if (currentState.getLastRegistrationResponse() != null) {
            clearedState.update(currentState.getLastRegistrationResponse());
        }
        mStateManager.replace(clearedState);

        Intent intent;
        if (mAuthService.getBrowserDescriptor().useCustomTab) {
            intent = mLogoutIntent.get().intent;
        } else {
            intent = new Intent(Intent.ACTION_VIEW);
        }

        intent.setPackage(mAuthService.getBrowserDescriptor().packageName);
        intent.setData(mLogoutRequest.get());
        startActivityForResult(intent, RC_AUTH);

        finish();
    }

    /**
     * Responds to changes in the login hint. After a "debounce" delay, warms up the browser
     * for a request with the new login hint; this avoids constantly re-initializing the
     * browser while the user is typing.
     */
    private final class LogoutStateChangeHandler implements TextWatcher {

        private static final int DEBOUNCE_DELAY_MS = 500;

        private Handler mHandler;
        private RecreateLogoutRequestTask mTask;

        LogoutStateChangeHandler() {
            mHandler = new Handler(Looper.getMainLooper());
            mTask = new LogoutActivity.RecreateLogoutRequestTask();
        }

        @Override
        public void beforeTextChanged(CharSequence cs, int start, int count, int after) {}

        @Override
        public void onTextChanged(CharSequence cs, int start, int before, int count) {
            mTask.cancel();
            mTask = new LogoutActivity.RecreateLogoutRequestTask();
            mHandler.postDelayed(mTask, DEBOUNCE_DELAY_MS);
        }

        @Override
        public void afterTextChanged(Editable ed) {}
    }

    private final class RecreateLogoutRequestTask implements Runnable {

        private final AtomicBoolean mCanceled = new AtomicBoolean();

        @Override
        public void run() {
            if (mCanceled.get()) {
                return;
            }

            createLogoutRequest(getLogoutState());
            warmUpBrowser();
        }

        public void cancel() {
            mCanceled.set(true);
        }
    }

    private String getLogoutState() {
        return ((EditText)findViewById(R.id.logout_state_value))
            .getText()
            .toString()
            .trim();
    }

    private void createLogoutRequest(@Nullable String logoutState) {
        Log.i(TAG, "Creating logout request for state: " + logoutState);

        AuthState currentState = mStateManager.getCurrent();

        // The AppAuth library does currently not support the use of the OpenID Logout Flow
        // So we "patch" the config here...
        Uri.Builder builder = new Uri.Builder();
        builder.scheme("https")
            .authority("www.authenix.eu")
            .appendPath("openid")
            .appendPath("logout")
            .appendQueryParameter("id_token_hint", currentState.getIdToken())
            .appendQueryParameter("post_logout_redirect_uri", mConfiguration.getRedirectUri().toString());

        if (!TextUtils.isEmpty(logoutState)) {
            builder.appendQueryParameter("state", logoutState);
        }

        mLogoutRequest.set(builder.build());
    }

    @MainThread
    private void initializeLogoutRequest() {
        createLogoutRequest(getLogoutState());
        warmUpBrowser();
        displayAuthorized();
    }

    private void warmUpBrowser() {
        mLogoutIntentLatch = new CountDownLatch(1);
        mExecutor.execute(() -> {
            Log.i(TAG, "Warming up browser instance for auth request");
            CustomTabsIntent.Builder intentBuilder =
                mAuthService.createCustomTabsIntentBuilder(mLogoutRequest.get());

            intentBuilder.setToolbarColor(getColorCompat(R.color.colorPrimary));
            mLogoutIntent.set(intentBuilder.build());
            mLogoutIntentLatch.countDown();
        });
    }

    private void recreateAuthorizationService() {
        if (mAuthService != null) {
            Log.i(TAG, "Discarding existing AuthService instance");
            mAuthService.dispose();
        }
        mAuthService = createAuthorizationService();
        mLogoutRequest.set(null);
        mLogoutIntent.set(null);
    }

    private AuthorizationService createAuthorizationService() {
        Log.i(TAG, "Creating authorization service");
        AppAuthConfiguration.Builder builder = new AppAuthConfiguration.Builder();
        builder.setBrowserMatcher(mBrowserMatcher);
        builder.setConnectionBuilder(mConfiguration.getConnectionBuilder());

        return new AuthorizationService(this, builder.build());
    }

    /**
     * Enumerates the browsers installed on the device and populates a spinner, allowing the
     * demo user to easily test the authorization flow against different browser and custom
     * tab configurations.
     */
    @MainThread
    private void configureBrowserSelector() {
        Spinner spinner = (Spinner) findViewById(R.id.browser_selector2);
        final BrowserSelectionAdapter adapter = new BrowserSelectionAdapter(this);
        spinner.setAdapter(adapter);
        spinner.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
            @Override
            public void onItemSelected(AdapterView<?> parent, View view, int position, long id) {
                BrowserSelectionAdapter.BrowserInfo info = adapter.getItem(position);
                if (info == null) {
                    mBrowserMatcher = AnyBrowserMatcher.INSTANCE;
                    return;
                } else {
                    mBrowserMatcher = new ExactBrowserMatcher(info.mDescriptor);
                }

                recreateAuthorizationService();
                createLogoutRequest(getLogoutState());
                warmUpBrowser();
            }

            @Override
            public void onNothingSelected(AdapterView<?> parent) {
                mBrowserMatcher = AnyBrowserMatcher.INSTANCE;
            }
        });
    }

    @TargetApi(Build.VERSION_CODES.M)
    @SuppressWarnings("deprecation")
    private int getColorCompat(@ColorRes int color) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            return getColor(color);
        } else {
            return getResources().getColor(color);
        }
    }

}
