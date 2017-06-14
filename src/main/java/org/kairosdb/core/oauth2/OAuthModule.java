package org.kairosdb.core.oauth2;

import com.google.inject.Singleton;
import com.google.inject.multibindings.Multibinder;
import com.google.inject.servlet.ServletModule;
import org.kairosdb.core.oauth2.cookie.OAuthCookieManager;
import org.kairosdb.core.oauth2.filter.OAuthFilter;
import org.kairosdb.core.oauth2.filter.OAuthRootFilter;
import org.kairosdb.core.oauth2.provider.OAuthProvider;
import org.kairosdb.core.oauth2.ressource.OAuthAuthorizeRessource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.Filter;
import java.util.HashSet;
import java.util.Properties;
import java.util.Set;

public class OAuthModule extends ServletModule
{
    private final static String FILTER_PREFIX = "kairosdb.oauth2.filters.";
    private final static String PROVIDER_PREFIX = "kairosdb.oauth2.provider";
    private final static String COOKIE_PREFIX = "kairosdb.oauth2.cookie_manager";

    private final Logger logger = LoggerFactory.getLogger(OAuthModule.class);
    private final ClassLoader classLoader = this.getClass().getClassLoader();
    private final Properties properties;

    public OAuthModule(Properties properties)
    {
        this.properties = properties;
    }

    @Override
    protected void configureServlets()
    {
        bind(OAuthRootFilter.class).in(Singleton.class);
        bind(OAuthAuthorizeRessource.class).in(Singleton.class);
        bind(OAuthService.class).in(Singleton.class);

        bind(OAuthRootFilter.Post.class).in(Singleton.class);
        bind(OAuthRootFilter.Get.class).in(Singleton.class);
        bind(OAuthRootFilter.Put.class).in(Singleton.class);
        bind(OAuthRootFilter.Patch.class).in(Singleton.class);
        bind(OAuthRootFilter.Delete.class).in(Singleton.class);

        bind(OAuthProvider.class).to(loadRequiredModule(PROVIDER_PREFIX, OAuthProvider.class)).in(Singleton.class);
        bind(OAuthCookieManager.class).to(loadRequiredModule(COOKIE_PREFIX, OAuthCookieManager.class)).in(Singleton.class);

        logger.info("OAuth2 Module initialized");
        configureFilter();
    }

    //region Modules loaders
    private <T> Class<? extends T> loadRequiredModule(String prefix, Class<T> originClazz)
    {
        String className = properties.getProperty(prefix);
        if (className == null)
            logger.error(String.format("Module '%s' required.", prefix));
        return loadModule(className, originClazz);
    }

    private <T> Class<? extends T> loadModule(String className, Class<T> originClazz)
    {
        if (className == null || className.isEmpty())
            return null;

        try
        {
            Class<?> clazz = classLoader.loadClass(className);
            if (originClazz.isAssignableFrom(clazz))
                return (Class<? extends T>) clazz;

            String failureMessage = String.format("Invalid class, must extend '%s'", originClazz.getName());
            logger.error(String.format("Unable to load module '%s': %s", className, failureMessage));

        } catch (ClassNotFoundException e)
        {
            logger.error(String.format("Unable to load module '%s': %s", className, "Class not found"));

        } catch (Exception e)
        {
            logger.error(String.format("Unable to load module '%s': %s", className, e.getMessage()));
        }
        return null;
    }
    //endregion

    //region Configurator
    private void configureFilter()
    {
        Multibinder<OAuthFilter> oAuthFilters = Multibinder.newSetBinder(binder(), OAuthFilter.class);

        for (String property : properties.stringPropertyNames())
        {
            if (property.startsWith(FILTER_PREFIX))
            {
                if (property.startsWith(FILTER_PREFIX + "module."))
                    configureModule(property, oAuthFilters);
                else if (property.startsWith(FILTER_PREFIX + "path."))
                    configurePath(property);
            }
        }
    }

    private void configureModule(String property, Multibinder<OAuthFilter> oAuthFilters)
    {
        Class<? extends OAuthFilter> clazz = loadModule(properties.getProperty(property), OAuthFilter.class);
        if (clazz != null)
        {
            oAuthFilters.addBinding().to(clazz);
            logger.info(String.format("\tCharge filter module '%s'", clazz.getName()));
        }
    }

    private void configurePath(String property)
    {
        String path = null;
        Set<MethodFilter> filterSet = new HashSet<>();

        for (String item : properties.getProperty(property).split("\\|"))
        {
            try
            {
                MethodFilter methodFilter = MethodFilter.valueOf(item.toUpperCase());
                filterSet.add(methodFilter);
            } catch (IllegalArgumentException e)
            {
                path = item;
            }
        }

        if (path == null)
            return;

        try
        {
            StringBuilder filterDesc = new StringBuilder();
            if (!filterSet.isEmpty())
            {
                for (MethodFilter filter : filterSet)
                {
                    filter(path).through(filter.toClass());
                    filterDesc.append(filter.toString()).append(" ");
                }
            } else
            {
                filter(path).through(MethodFilter.GET.toClass());
                filterDesc.append("GET");
            }
            logger.info(String.format("\tNew filter on '%s' (%s)", path, filterDesc.toString().trim()));
        } catch (Exception e)
        {
            logger.error(String.format("\tFilter path '%s' not valid (%s)", path, e.getMessage()));
        }
    }
    //endregion

    enum MethodFilter
    {
        POST(OAuthRootFilter.Post.class),
        GET(OAuthRootFilter.Get.class),
        PUT(OAuthRootFilter.Put.class),
        PATCH(OAuthRootFilter.Patch.class),
        DELETE(OAuthRootFilter.Delete.class);


        private final Class<? extends Filter> filter;

        MethodFilter(Class<? extends Filter> filter)
        {
            this.filter = filter;
        }

        public Class<? extends Filter> toClass()
        {
            return filter;
        }
    }
}