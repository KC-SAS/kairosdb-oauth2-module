package org.kairosdb.security.oauth2.core;

import com.google.inject.AbstractModule;
import com.google.inject.Inject;
import com.google.inject.Singleton;
import com.google.inject.binder.LinkedBindingBuilder;
import com.google.inject.name.Names;
import org.kairosdb.security.auth.authenticator.AuthenticatorModule;
import org.kairosdb.security.auth.core.FilterManager;
import org.kairosdb.security.oauth2.core.resource.OAuthAuthorizeResource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Properties;
import java.util.Set;
import java.util.function.Consumer;

import static org.kairosdb.security.auth.core.AuthenticationManagerModule.KAIROSDB_SECURITY_PREFIX;
import static org.kairosdb.security.auth.utils.Filters.filtersFrom;
import static org.kairosdb.security.auth.utils.Modules.loadClass;

public class OAuthModule extends AbstractModule implements AuthenticatorModule
{
    private static final String OAUTH_PREFIX = KAIROSDB_SECURITY_PREFIX + "oauth2.";
    private static final String RESPONSE_WEIGHT_PREFIX = OAUTH_PREFIX + "priority_weight";
    private static final String PROVIDER_PREFIX = OAUTH_PREFIX + "provider";
    private static final String COOKIE_PREFIX = OAUTH_PREFIX + "cookie.manager";
    private static final String COOKIE_NAME_PREFIX = OAUTH_PREFIX + "cookie.name";
    private static final String FILTER_PATH_PREFIX = OAUTH_PREFIX + "filters.path.";

    private static final String ERR_PROPERTY_NOT_SET = "%s not set, default value used ('%s')";
    private static final String ERR_UNABLE_TO_LOAD = "Unable to load module '%s': %s";

    private static final String COOKIE_NAME_DEFAULT = "oauthToken";
    private static final int RESPONSE_WEIGHT_DEFAULT = 1024;

    private static final Logger logger = LoggerFactory.getLogger(OAuthModule.class);
    private final Properties properties;

    @Inject
    public OAuthModule(Properties properties)
    {
        this.properties = properties;
    }

    @Override
    protected void configure()
    {
        bind(OAuthAuthorizeResource.class).in(Singleton.class);
        bind(OAuthService.class).asEagerSingleton();
        bind(OAuthFilter.class).in(Singleton.class);

        bind(OAuthProvider.class).to(requiredModule(PROVIDER_PREFIX, OAuthProvider.class)).in(Singleton.class);
        bind(OAuthCookieManager.class).to(requiredModule(COOKIE_PREFIX, OAuthCookieManager.class)).in(Singleton.class);

        String cookieName = properties.getProperty(COOKIE_NAME_PREFIX);
        if (cookieName == null || cookieName.isEmpty())
        {
            logger.warn(String.format(ERR_PROPERTY_NOT_SET, COOKIE_NAME_PREFIX, COOKIE_NAME_DEFAULT));
            cookieName = "oauthToken";
        }
        bind(String.class).annotatedWith(Names.named("cookie_name")).toInstance(cookieName);

        LinkedBindingBuilder<Integer> response_weight = bind(int.class).annotatedWith(Names.named("response_weight"));
        try
        {
            String responseWeight = properties.getProperty(RESPONSE_WEIGHT_PREFIX);
            response_weight.toInstance(Integer.parseInt(responseWeight));
        } catch (Exception ignore)
        {
            logger.warn(String.format(ERR_PROPERTY_NOT_SET, RESPONSE_WEIGHT_PREFIX, RESPONSE_WEIGHT_DEFAULT));
            response_weight.toInstance(1024);
        }

        logger.info("OAuth2 authentication initialized");
    }

    @Override
    public void configure(Properties properties, FilterManager filterManager)
    {
        Set<Consumer<FilterManager>> filter = filtersFrom(properties, FILTER_PATH_PREFIX, OAuthFilter.class);
        logger.info(String.format("%d filter(s) found", filter.size()));
        filter.forEach(f -> f.accept(filterManager));
        logger.info("OAuth2 authentication configured");
    }

    private <T> Class<? extends T> requiredModule(String prefix, Class<T> originClazz)
    {
        String className = properties.getProperty(prefix);
        if (className == null)
            logger.error(String.format("Module '%s' required.", prefix));

        return loadModule(className, originClazz);
    }

    private <T> Class<? extends T> loadModule(String className, Class<T> originClazz)
    {
        try
        {
            return loadClass(className, originClazz);

        } catch (IllegalArgumentException ignore)
        {

        } catch (ClassNotFoundException e)
        {
            logger.error(String.format(ERR_UNABLE_TO_LOAD, className, "Class not found"));

        } catch (Exception e)
        {
            logger.error(String.format(ERR_UNABLE_TO_LOAD, className, e.getMessage()));
        }
        return null;
    }
}
