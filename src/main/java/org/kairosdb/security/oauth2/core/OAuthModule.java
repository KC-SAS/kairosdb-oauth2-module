package org.kairosdb.security.oauth2.core;

import com.google.inject.AbstractModule;
import com.google.inject.Singleton;
import com.google.inject.multibindings.Multibinder;
import com.google.inject.name.Names;
import org.kairosdb.security.auth.AuthenticationModule;
import org.kairosdb.security.auth.core.FilterManager;
import org.kairosdb.security.auth.core.Utils;
import org.kairosdb.security.oauth2.core.resource.OAuthAuthorizeResource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Properties;
import java.util.Set;
import java.util.function.Consumer;

import static org.kairosdb.security.auth.core.Utils.filtersFrom;

public class OAuthModule extends AbstractModule implements AuthenticationModule
{
    private static final String FILTER_PATH_PREFIX = "kairosdb.security.oauth2.filter_path.";
    private static final String MODULE_PREFIX = "kairosdb.security.oauth2.modules.";
    private static final String PROVIDER_PREFIX = "kairosdb.security.oauth2.provider";
    private static final String COOKIE_PREFIX = "kairosdb.security.oauth2.cookie.manager";
    private static final String COOKIE_NAME_PREFIX = "kairosdb.security.oauth2.cookie.name";
    private static final String RESPONSE_WEIGHT_PREFIX = "kairosdb.security.oauth2.response_weight";

    private static final Logger logger = LoggerFactory.getLogger(OAuthModule.class);
    private final Properties properties;

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
            cookieName = "oauthToken";
        bind(String.class).annotatedWith(Names.named("cookie_name")).toInstance(cookieName);

        try
        {
            String responseWeight = properties.getProperty(RESPONSE_WEIGHT_PREFIX);
            bind(int.class).annotatedWith(Names.named("response_weight")).toInstance(Integer.parseInt(responseWeight));
        } catch (Exception ignore)
        {
            bind(int.class).annotatedWith(Names.named("response_weight")).toInstance(1024);
        }

        bindPlugins();
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

    private void bindPlugins()
    {
        Multibinder<OAuthPlugin> oAuthFilters = Multibinder.newSetBinder(binder(), OAuthPlugin.class);

        for (Object okey : properties.keySet())
        {
            String key = okey.toString();
            if (key.startsWith(MODULE_PREFIX))
            {
                Class<? extends OAuthPlugin> plugin = loadModule(properties.getProperty(key), OAuthPlugin.class);
                if (plugin != null)
                {
                    logger.info(String.format("OAuth2: Load oauth plugin '%s'", plugin.getName()));
                    oAuthFilters.addBinding().to(plugin);
                }
            }
        }
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
            return Utils.loadModule(className, originClazz);

        } catch (IllegalArgumentException ignore)
        {

        } catch (ClassNotFoundException e)
        {
            logger.error(String.format("Unable to load module '%s': %s", className, "Class not found"));

        } catch (Exception e)
        {
            logger.error(String.format("Unable to load module '%s': %s", className, e.getMessage()));
        }
        return null;
    }
}