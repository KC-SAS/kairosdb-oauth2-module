package org.kairosdb.core.oauth2;

import com.google.inject.Singleton;
import com.google.inject.multibindings.Multibinder;
import com.google.inject.servlet.ServletModule;
import org.kairosdb.core.oauth2.cookie.OAuthCookieManager;
import org.kairosdb.core.oauth2.filter.OAuthBaseFilter;
import org.kairosdb.core.oauth2.filter.OAuthFilter;
import org.kairosdb.core.oauth2.provider.OAuthProvider;
import org.kairosdb.core.oauth2.ressource.OAuthAuthorizeRessource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.Filter;
import java.util.*;

public class OAuthModule extends ServletModule
{
    private final static String FILTER_PREFIX = "kairosdb.oauth2.filters.";
    private final static String PROVIDER_PREFIX = "kairosdb.oauth2.provider";
    private final static String COOKIE_PREFIX = "kairosdb.oauth2.cookie_manager";

    private final static String REQUIRED_NOTFOUND = "Module '%s' required.";
    private final static String LOAD_FAILURE = "Unable to load module '%s': %s";

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
        bind(OAuthBaseFilter.class).in(Singleton.class);
        bind(OAuthAuthorizeRessource.class).in(Singleton.class);
        bind(OAuthService.class).in(Singleton.class);

        bind(OAuthBaseFilter.Post.class);
        bind(OAuthBaseFilter.Get.class);
        bind(OAuthBaseFilter.Put.class);
        bind(OAuthBaseFilter.Patch.class);
        bind(OAuthBaseFilter.Delete.class);

        bind(OAuthProvider.class).to(loadRequiredModule(PROVIDER_PREFIX, OAuthProvider.class)).in(Singleton.class);
        bind(OAuthCookieManager.class).to(loadRequiredModule(COOKIE_PREFIX, OAuthCookieManager.class)).in(Singleton.class);

        configureFilter();
    }

    //region Modules loaders
    private <T> Class<? extends T> loadRequiredModule(String prefix, Class<T> originClazz)
    {
        String className = properties.getProperty(prefix);
        if (className == null)
            logger.error(String.format(REQUIRED_NOTFOUND, prefix));
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
            logger.error(String.format(LOAD_FAILURE, className, failureMessage));

        } catch (ClassNotFoundException e)
        {
            logger.error(String.format(LOAD_FAILURE, className, "Class not found"));

        } catch (Exception e)
        {
            logger.error(String.format(LOAD_FAILURE, className, e.getMessage()));
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
            oAuthFilters.addBinding().to(clazz);
    }

    private void configurePath(String property)
    {
        String path = null;
        Set<Class<? extends Filter>> filters = new HashSet<>();

        for (String item : properties.getProperty(property).split("|"))
        {
            try
            {
                switch (MethodFilter.valueOf(item.toUpperCase()))
                {
                    case POST:
                        filters.add(MethodFilter.POST.toClass());
                        break;
                    case GET:
                        filters.add(MethodFilter.GET.toClass());
                        break;
                    case PUT:
                        filters.add(MethodFilter.PUT.toClass());
                        break;
                    case PATCH:
                        filters.add(MethodFilter.PATCH.toClass());
                        break;
                    case DELETE:
                        filters.add(MethodFilter.DELETE.toClass());
                        break;
                }
            }
            catch (IllegalArgumentException e)
            {
                path = item;
            }
        }

        if (path == null) return;

        if (!filters.isEmpty())
            for (Class<? extends Filter> filter : filters)
                filter(path).through(filter);
        else
            filter(path).through(MethodFilter.GET.toClass());
    }
    //endregion

    enum MethodFilter
    {
        POST(OAuthBaseFilter.Post.class),
        GET(OAuthBaseFilter.Get.class),
        PUT(OAuthBaseFilter.Put.class),
        PATCH(OAuthBaseFilter.Patch.class),
        DELETE(OAuthBaseFilter.Delete.class);


        private final Class<? extends Filter> filter;

        private MethodFilter(Class<? extends Filter> filter)
        {
            this.filter = filter;
        }

        public Class<? extends Filter> toClass()
        {
            return filter;
        }
    }
}