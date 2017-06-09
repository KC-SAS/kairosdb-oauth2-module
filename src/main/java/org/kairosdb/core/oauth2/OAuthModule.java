package org.kairosdb.core.oauth2;

import com.google.inject.Singleton;
import com.google.inject.servlet.ServletModule;
import org.kairosdb.core.oauth2.cookie.OAuthCookieManager;
import org.kairosdb.core.oauth2.filter.OAuthFilter;
import org.kairosdb.core.oauth2.provider.OAuthProvider;
import org.kairosdb.core.oauth2.ressource.OAuthAuthorizeRessource;
import org.kairosdb.oauth2.cookie.SimpleCookieManager;
import org.kairosdb.oauth2.provider.OAuthGoogleProvider;

public class OAuthModule extends ServletModule
{
    @Override
    protected void configureServlets()
    {
        bind(OAuthFilter.class).in(Singleton.class);
        bind(OAuthAuthorizeRessource.class).in(Singleton.class);// Static class -> NOT REIMPLEMENT IT

        bind(OAuthService.class).in(Singleton.class);
        bind(OAuthProvider.class).to(OAuthGoogleProvider.class).in(Singleton.class); //From properties
        bind(OAuthCookieManager.class).to(SimpleCookieManager.class).in(Singleton.class); //From properties

        filter("/api/*").through(OAuthFilter.class); //Charge filter from properties
    }
}
