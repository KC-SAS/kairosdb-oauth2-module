package org.kairosdb.security.oauth2.core;

import com.google.inject.AbstractModule;
import com.google.inject.Inject;
import com.google.inject.Singleton;
import com.google.inject.multibindings.Multibinder;
import org.kairosdb.security.auth.AuthenticationModule;
import org.kairosdb.security.auth.core.FilterManager;
import org.kairosdb.security.auth.core.Utils;
import org.kairosdb.security.oauth2.core.ressource.OAuthAuthorizeRessource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Properties;
import java.util.Set;
import java.util.function.Consumer;

import static org.kairosdb.security.auth.core.Utils.filterFrom;

public class OAuthModule extends AbstractModule implements AuthenticationModule
{
    private final static String FILTER_PATH_PREFIX = "kairosdb.security.oauth2.filter_path.";
    private final static String MODULE_PREFIX = "kairosdb.security.oauth2.modules.";
    private final static String PROVIDER_PREFIX = "kairosdb.security.oauth2.provider";
    private final static String COOKIE_PREFIX = "kairosdb.security.oauth2.cookie_manager";

    private final Logger logger = LoggerFactory.getLogger(OAuthModule.class);
    private final Properties properties;

    @Inject
    public OAuthModule(Properties properties)
    {
        this.properties = properties;
    }

    @Override
    protected void configure()
    {
        bind(OAuthAuthorizeRessource.class).in(Singleton.class);
        bind(OAuthService.class).asEagerSingleton();
        bind(OAuthFilter.class).in(Singleton.class);

        bind(OAuthProvider.class).to(requiredModule(PROVIDER_PREFIX, OAuthProvider.class)).in(Singleton.class);
        bind(OAuthCookieManager.class).to(requiredModule(COOKIE_PREFIX, OAuthCookieManager.class)).in(Singleton.class);

        bindPlugins();
        logger.info("OAuth2: Module initialized");
    }

    @Override
    public void configure(Properties properties, FilterManager filterManager)
    {
        logger.info("Configuration du l'oauth");
        Set<Consumer<FilterManager>> filter = filterFrom(properties, FILTER_PATH_PREFIX, OAuthFilter.class);
        logger.info(String.format("%d filter found", filter.size()));
        filter.forEach(f -> f.accept(filterManager));
        logger.info("OAuth2: Module configured");
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