package com.tangem;

import android.app.Application;
import android.support.v7.app.AppCompatDelegate;

public class AppController extends Application {

    /**
     * A singleton instance of the application class for easy access in other places
     */
    private static AppController sInstance;

    public AppController() {
        super();
    }

    static {
        AppCompatDelegate.setCompatVectorFromResourcesEnabled(true);
    }

    @Override
    public void onCreate() {
        super.onCreate();
        // initialize the singleton
        sInstance = this;
    }

    /**
     * @return singleton instance
     */
    public static synchronized AppController getInstance() {
        return sInstance;
    }

}