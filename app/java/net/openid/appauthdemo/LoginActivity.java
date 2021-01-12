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
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.Editable;
import android.text.TextUtils;
import android.text.TextWatcher;
import android.util.ArrayMap;
import android.util.Log;
import android.view.View;
import android.widget.AdapterView;
import android.widget.AdapterView.OnItemSelectedListener;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.Spinner;
import android.widget.TextView;
import androidx.annotation.AnyThread;
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
import net.openid.appauth.AuthorizationServiceConfiguration;
import net.openid.appauth.ClientSecretBasic;
import net.openid.appauth.RegistrationRequest;
import net.openid.appauth.RegistrationResponse;
import net.openid.appauth.ResponseTypeValues;
import net.openid.appauth.browser.AnyBrowserMatcher;
import net.openid.appauth.browser.BrowserMatcher;
import net.openid.appauth.browser.ExactBrowserMatcher;
import net.openid.appauthdemo.BrowserSelectionAdapter.BrowserInfo;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Demonstrates the usage of the AppAuth to authorize a user with an OAuth2 / OpenID Connect
 * provider. Based on the configuration provided in `res/raw/auth_config.json`, the code
 * contained here will:
 *
 * - Retrieve an OpenID Connect discovery document for the provider, or use a local static
 *   configuration.
 * - Utilize dynamic client registration, if no static client id is specified.
 * - Initiate the authorization request using the built-in heuristics or a user-selected browser.
 *
 * _NOTE_: From a clean checkout of this project, the authorization service is not configured.
 * Edit `res/values/auth_config.xml` to provide the required configuration properties. See the
 * README.md in the app/ directory for configuration instructions, and the adjacent IDP-specific
 * instructions.
 */
public final class LoginActivity extends AppCompatActivity {

    private static final String TAG = "LoginActivity";
    private static final String EXTRA_FAILED = "failed";
    private static final int RC_AUTH = 100;

    private AuthorizationService mAuthService;
    private AuthStateManager mAuthStateManager;
    private Configuration mConfiguration;

    private final AtomicReference<String> mClientId = new AtomicReference<>();
    private final AtomicReference<AuthorizationRequest> mAuthRequest = new AtomicReference<>();
    private final AtomicReference<CustomTabsIntent> mAuthIntent = new AtomicReference<>();
    private CountDownLatch mAuthIntentLatch = new CountDownLatch(1);
    private ExecutorService mExecutor;

    private boolean mUsePendingIntents;

    @NonNull
    private BrowserMatcher mBrowserMatcher = AnyBrowserMatcher.INSTANCE;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        mExecutor = Executors.newSingleThreadExecutor();
        mAuthStateManager = AuthStateManager.getInstance(this);
        mConfiguration = Configuration.getInstance(this);

        if (mAuthStateManager.getCurrent().isAuthorized()
                && !mConfiguration.hasConfigurationChanged()) {
            Log.i(TAG, "User is already authenticated, proceeding to token activity");
            startActivity(new Intent(this, TokenActivity.class));
            finish();
            return;
        }

        setContentView(R.layout.activity_login);

        findViewById(R.id.retry).setOnClickListener((View view) ->
                mExecutor.submit(this::initializeAppAuth));
        findViewById(R.id.start_auth).setOnClickListener((View view) -> startAuth());

        ((EditText)findViewById(R.id.login_hint_value)).addTextChangedListener(
                new LoginHintChangeHandler());

        if (!mConfiguration.isValid()) {
            displayError(mConfiguration.getConfigurationError(), false);
            return;
        }

        configureBrowserSelector();
        if (mConfiguration.hasConfigurationChanged()) {
            // discard any existing authorization state due to the change of configuration
            Log.i(TAG, "Configuration change detected, discarding old state");
            mAuthStateManager.replace(new AuthState());
            mConfiguration.acceptConfiguration();
        }

        if (getIntent().getBooleanExtra(EXTRA_FAILED, false)) {
            displayAuthCancelled();
        }

        displayLoading("Initializing");
        mExecutor.submit(this::initializeAppAuth);
    }

    @Override
    protected void onStart() {
        super.onStart();
        if (mExecutor.isShutdown()) {
            mExecutor = Executors.newSingleThreadExecutor();
        }
    }

    @Override
    protected void onStop() {
        super.onStop();
        mExecutor.shutdownNow();
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();

        if (mAuthService != null) {
            mAuthService.dispose();
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        displayAuthOptions();
        if (resultCode == RESULT_CANCELED) {
            displayAuthCancelled();
        } else {
            Intent intent = new Intent(this, TokenActivity.class);
            intent.putExtras(data.getExtras());
            startActivity(intent);
        }
    }

    @MainThread
    void startAuth() {
        displayLoading("Making authorization request");

        mUsePendingIntents = ((CheckBox) findViewById(R.id.pending_intents_checkbox)).isChecked();

        // WrongThread inference is incorrect for lambdas
        // noinspection WrongThread
        mExecutor.submit(this::doAuth);
    }

    /**
     * Initializes the authorization service configuration if necessary, either from the local
     * static values or by retrieving an OpenID discovery document.
     */
    @WorkerThread
    private void initializeAppAuth() {
        Log.i(TAG, "Initializing AppAuth");
        recreateAuthorizationService();

        if (mAuthStateManager.getCurrent().getAuthorizationServiceConfiguration() != null) {
            // configuration is already created, skip to client initialization
            Log.i(TAG, "auth config already established");
            initializeClient();
            return;
        }

        // if we are not using discovery, build the authorization service configuration directly
        // from the static configuration values.
        if (mConfiguration.getDiscoveryUri() == null) {
            Log.i(TAG, "Creating auth config from res/raw/auth_config.json");
            AuthorizationServiceConfiguration config = new AuthorizationServiceConfiguration(
                    mConfiguration.getAuthEndpointUri(),
                    mConfiguration.getTokenEndpointUri(),
                    mConfiguration.getRegistrationEndpointUri());

            mAuthStateManager.replace(new AuthState(config));
            initializeClient();
            return;
        }

        // WrongThread inference is incorrect for lambdas
        // noinspection WrongThread
        runOnUiThread(() -> displayLoading("Retrieving discovery document"));
        Log.i(TAG, "Retrieving OpenID discovery doc");
        AuthorizationServiceConfiguration.fetchFromUrl(
                mConfiguration.getDiscoveryUri(),
                this::handleConfigurationRetrievalResult,
                mConfiguration.getConnectionBuilder());
    }

    @MainThread
    private void handleConfigurationRetrievalResult(
            AuthorizationServiceConfiguration config,
            AuthorizationException ex) {
        if (config == null) {
            Log.i(TAG, "Failed to retrieve discovery document", ex);
            displayError("Failed to retrieve discovery document: " + ex.getMessage(), true);
            return;
        }

        Log.i(TAG, "Discovery document retrieved");
        mAuthStateManager.replace(new AuthState(config));
        mExecutor.submit(this::initializeClient);
    }

    /**
     * Initiates a dynamic registration request if a client ID is not provided by the static
     * configuration.
     */
    @WorkerThread
    private void initializeClient() {
        if (mConfiguration.getClientId() != null) {
            Log.i(TAG, "Using static client ID: " + mConfiguration.getClientId());
            // use a statically configured client ID
            mClientId.set(mConfiguration.getClientId());
            runOnUiThread(this::initializeAuthRequest);
            return;
        }

        RegistrationResponse lastResponse =
                mAuthStateManager.getCurrent().getLastRegistrationResponse();
        if (lastResponse != null) {
            Log.i(TAG, "Using dynamic client ID: " + lastResponse.clientId);
            // already dynamically registered a client ID
            mClientId.set(lastResponse.clientId);
            runOnUiThread(this::initializeAuthRequest);
            return;
        }

        // WrongThread inference is incorrect for lambdas
        // noinspection WrongThread
        runOnUiThread(() -> displayLoading("Dynamically registering client"));
        Log.i(TAG, "Dynamically registering client");

        String post_logout_redirect_uri =  mConfiguration.getRedirectUri().toString();
        Map<String, String> params = new HashMap<>();
        params.put("scope", "openid profile offline_access");
        params.put("contacts", "ljs@treasure-island.site");
        params.put("operator_name", "Treasure Island Inc.");
        params.put("operator_uri", "https://www.treasure-island.site");
        params.put("operator_privacy", ":-)");
        params.put("operator_address", "Treasure Island");
        params.put("operator_user", "Long John Silver");
        params.put("operator_country", "DL");
        params.put("client_name", "OpenID AppAuth Demo - Android");
        params.put("software_id", "aaec8bf1-9c75-4575-b0ff-3e1769782055");
        params.put("software_version", "0.1");
        params.put("post_logout_redirect_uris", post_logout_redirect_uri);
        params.put("logo_uri", "data:image/png;base64,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");

        RegistrationRequest registrationRequest = new RegistrationRequest.Builder(
                mAuthStateManager.getCurrent().getAuthorizationServiceConfiguration(),
                Collections.singletonList(mConfiguration.getRedirectUri()))
                .setTokenEndpointAuthenticationMethod(ClientSecretBasic.NAME)
                .setAdditionalParameters(params)
                .build();

        mAuthService.performRegistrationRequest(
                registrationRequest,
                this::handleRegistrationResponse);
    }

    @MainThread
    private void handleRegistrationResponse(
            RegistrationResponse response,
            AuthorizationException ex) {
        mAuthStateManager.updateAfterRegistration(response, ex);
        if (response == null) {
            Log.i(TAG, "Failed to dynamically register client", ex);
            displayErrorLater("Failed to register client: " + ex.getMessage(), true);
            return;
        }

        Log.i(TAG, "Dynamically registered client: " + response);
        if (response.clientId == null)
        {
            Log.i(TAG, "Failed to dynamically register client", ex);
            displayErrorLater("Failed to register client: " + response.jsonSerializeString(), true);
            return;
        }
        else {
            Log.i(TAG, "Dynamically registered client: " + response.clientId);
            mClientId.set(response.clientId);
            initializeAuthRequest();
        }
    }

    /**
     * Enumerates the browsers installed on the device and populates a spinner, allowing the
     * demo user to easily test the authorization flow against different browser and custom
     * tab configurations.
     */
    @MainThread
    private void configureBrowserSelector() {
        Spinner spinner = (Spinner) findViewById(R.id.browser_selector);
        final BrowserSelectionAdapter adapter = new BrowserSelectionAdapter(this);
        spinner.setAdapter(adapter);
        spinner.setOnItemSelectedListener(new OnItemSelectedListener() {
            @Override
            public void onItemSelected(AdapterView<?> parent, View view, int position, long id) {
                BrowserInfo info = adapter.getItem(position);
                if (info == null) {
                    mBrowserMatcher = AnyBrowserMatcher.INSTANCE;
                    return;
                } else {
                    mBrowserMatcher = new ExactBrowserMatcher(info.mDescriptor);
                }

                recreateAuthorizationService();
                createAuthRequest(getLoginHint());
                warmUpBrowser();
            }

            @Override
            public void onNothingSelected(AdapterView<?> parent) {
                mBrowserMatcher = AnyBrowserMatcher.INSTANCE;
            }
        });
    }

    /**
     * Performs the authorization request, using the browser selected in the spinner,
     * and a user-provided `login_hint` if available.
     */
    @WorkerThread
    private void doAuth() {
        try {
            mAuthIntentLatch.await();
        } catch (InterruptedException ex) {
            Log.w(TAG, "Interrupted while waiting for auth intent");
        }

        if (mUsePendingIntents) {
            Intent completionIntent = new Intent(this, TokenActivity.class);
            Intent cancelIntent = new Intent(this, LoginActivity.class);
            cancelIntent.putExtra(EXTRA_FAILED, true);
            cancelIntent.setFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP);

            mAuthService.performAuthorizationRequest(
                    mAuthRequest.get(),
                    PendingIntent.getActivity(this, 0, completionIntent, 0),
                    PendingIntent.getActivity(this, 0, cancelIntent, 0),
                    mAuthIntent.get());
        } else {
            Intent intent = mAuthService.getAuthorizationRequestIntent(
                    mAuthRequest.get(),
                    mAuthIntent.get());
            startActivityForResult(intent, RC_AUTH);
        }
    }

    private void recreateAuthorizationService() {
        if (mAuthService != null) {
            Log.i(TAG, "Discarding existing AuthService instance");
            mAuthService.dispose();
        }
        mAuthService = createAuthorizationService();
        mAuthRequest.set(null);
        mAuthIntent.set(null);
    }

    private AuthorizationService createAuthorizationService() {
        Log.i(TAG, "Creating authorization service");
        AppAuthConfiguration.Builder builder = new AppAuthConfiguration.Builder();
        builder.setBrowserMatcher(mBrowserMatcher);
        builder.setConnectionBuilder(mConfiguration.getConnectionBuilder());

        return new AuthorizationService(this, builder.build());
    }

    @MainThread
    private void displayLoading(String loadingMessage) {
        findViewById(R.id.loading_container).setVisibility(View.VISIBLE);
        findViewById(R.id.auth_container).setVisibility(View.GONE);
        findViewById(R.id.error_container).setVisibility(View.GONE);

        ((TextView)findViewById(R.id.loading_description)).setText(loadingMessage);
    }

    @MainThread
    private void displayError(String error, boolean recoverable) {
        findViewById(R.id.error_container).setVisibility(View.VISIBLE);
        findViewById(R.id.loading_container).setVisibility(View.GONE);
        findViewById(R.id.auth_container).setVisibility(View.GONE);

        ((TextView)findViewById(R.id.error_description)).setText(error);
        findViewById(R.id.retry).setVisibility(recoverable ? View.VISIBLE : View.GONE);
    }

    // WrongThread inference is incorrect in this case
    @SuppressWarnings("WrongThread")
    @AnyThread
    private void displayErrorLater(final String error, final boolean recoverable) {
        runOnUiThread(() -> displayError(error, recoverable));
    }

    @MainThread
    private void initializeAuthRequest() {
        createAuthRequest(getLoginHint());
        warmUpBrowser();
        displayAuthOptions();
    }

    @MainThread
    private void displayAuthOptions() {
        findViewById(R.id.auth_container).setVisibility(View.VISIBLE);
        findViewById(R.id.loading_container).setVisibility(View.GONE);
        findViewById(R.id.error_container).setVisibility(View.GONE);

        AuthState state = mAuthStateManager.getCurrent();
        AuthorizationServiceConfiguration config = state.getAuthorizationServiceConfiguration();

        String authEndpointStr;
        if (config.discoveryDoc != null) {
            authEndpointStr = "Discovered auth endpoint: \n";
        } else {
            authEndpointStr = "Static auth endpoint: \n";
        }
        authEndpointStr += config.authorizationEndpoint;
        ((TextView)findViewById(R.id.auth_endpoint)).setText(authEndpointStr);

        String clientIdStr;
        if (state.getLastRegistrationResponse() != null) {
            clientIdStr = "Dynamic client ID: \n";
        } else {
            clientIdStr = "Static client ID: \n";
        }
        clientIdStr += mClientId;
        ((TextView)findViewById(R.id.client_id)).setText(clientIdStr);
    }

    private void displayAuthCancelled() {
        Snackbar.make(findViewById(R.id.coordinator),
                "Authorization canceled",
                Snackbar.LENGTH_SHORT)
                .show();
    }

    private void warmUpBrowser() {
        mAuthIntentLatch = new CountDownLatch(1);
        mExecutor.execute(() -> {
            Log.i(TAG, "Warming up browser instance for auth request");
            CustomTabsIntent.Builder intentBuilder =
                    mAuthService.createCustomTabsIntentBuilder(mAuthRequest.get().toUri());
            intentBuilder.setToolbarColor(getColorCompat(R.color.colorPrimary));
            mAuthIntent.set(intentBuilder.build());
            mAuthIntentLatch.countDown();
        });
    }

    private void createAuthRequest(@Nullable String loginHint) {
        Log.i(TAG, "Creating auth request for login hint: " + loginHint);
        AuthorizationRequest.Builder authRequestBuilder = new AuthorizationRequest.Builder(
                mAuthStateManager.getCurrent().getAuthorizationServiceConfiguration(),
                mClientId.get(),
                ResponseTypeValues.CODE + ' ' + ResponseTypeValues.ID_TOKEN,
                mConfiguration.getRedirectUri())
                .setScope(mConfiguration.getScope());

        if (!TextUtils.isEmpty(loginHint)) {
            authRequestBuilder.setLoginHint(loginHint);
        }

        authRequestBuilder.setPrompt("login select_account");

        mAuthRequest.set(authRequestBuilder.build());
    }

    private String getLoginHint() {
        return ((EditText)findViewById(R.id.login_hint_value))
                .getText()
                .toString()
                .trim();
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

    /**
     * Responds to changes in the login hint. After a "debounce" delay, warms up the browser
     * for a request with the new login hint; this avoids constantly re-initializing the
     * browser while the user is typing.
     */
    private final class LoginHintChangeHandler implements TextWatcher {

        private static final int DEBOUNCE_DELAY_MS = 500;

        private Handler mHandler;
        private RecreateAuthRequestTask mTask;

        LoginHintChangeHandler() {
            mHandler = new Handler(Looper.getMainLooper());
            mTask = new RecreateAuthRequestTask();
        }

        @Override
        public void beforeTextChanged(CharSequence cs, int start, int count, int after) {}

        @Override
        public void onTextChanged(CharSequence cs, int start, int before, int count) {
            mTask.cancel();
            mTask = new RecreateAuthRequestTask();
            mHandler.postDelayed(mTask, DEBOUNCE_DELAY_MS);
        }

        @Override
        public void afterTextChanged(Editable ed) {}
    }

    private final class RecreateAuthRequestTask implements Runnable {

        private final AtomicBoolean mCanceled = new AtomicBoolean();

        @Override
        public void run() {
            if (mCanceled.get()) {
                return;
            }

            createAuthRequest(getLoginHint());
            warmUpBrowser();
        }

        public void cancel() {
            mCanceled.set(true);
        }
    }
}
