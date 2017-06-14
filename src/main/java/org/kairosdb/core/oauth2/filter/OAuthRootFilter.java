package org.kairosdb.core.oauth2.filter;

import com.google.inject.Inject;
import org.kairosdb.core.oauth2.OAuthService;
import org.kairosdb.core.oauth2.client.OAuthClient;
import org.kairosdb.core.oauth2.exceptions.OAuthFlowException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Set;

public class OAuthRootFilter
{
    private static final Logger logger = LoggerFactory.getLogger(OAuthRootFilter.class);

    static class GenericMethodFilter implements Filter
    {
        private OAuthService oAuthService;
        private Set<OAuthFilter> filters;

        GenericMethodFilter(OAuthService oAuthService, Set<OAuthFilter> filters)
        {
            this.oAuthService = oAuthService;
            this.filters = filters;
        }

        @Override
        public void init(FilterConfig filterConfig) throws ServletException { }

        @Override
        public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain)
                throws IOException, ServletException
        {
            final HttpServletRequest httpRequest = (HttpServletRequest) servletRequest;
            final HttpServletResponse httpResponse = (HttpServletResponse) servletResponse;

            if (httpRequest.getMethod().equalsIgnoreCase(this.getClass().getSimpleName()))
                doFilter(httpRequest, httpResponse);
            filterChain.doFilter(servletRequest, servletResponse);
        }

        @Override
        public void destroy() { }

        //region Base authentication filter
        private void authenticateClient(OAuthService.OAuthPacket requestPacket,
                                        HttpServletRequest httpRequest,
                                        HttpServletResponse httpResponse)
                throws URISyntaxException, IOException, OAuthFlowException
        {
            final OAuthService.OAuthPacket responsePacket = oAuthService.startAuthentication(requestPacket, new URI(httpRequest.getRequestURI()));
            logger.warn(String.format("'%s' not allowed to access to '%s'.", requestPacket.getRemoteAddr(), httpRequest.getRequestURI()));

            responsePacket.toResponse(httpResponse);
        }

        private OAuthClient authorizedClient(HttpServletRequest httpRequest, HttpServletResponse httpResponse) throws IOException
        {
            try
            {
                URI redirectUri = new URI(oAuthService.getRedirectionUri());
                if (httpRequest.getRequestURI().equals(redirectUri.getPath()))
                    return null;

                final OAuthService.OAuthPacket requestPacket = OAuthService.packetFrom(httpRequest, oAuthService.getCookieManager());
                final OAuthClient client = oAuthService.getClient(requestPacket);

                if (client != null && client.isAuthenticated())
                    return client;

                authenticateClient(requestPacket, httpRequest, httpResponse);
                return null;

            } catch (Exception e)
            {
                logger.error(e.getMessage(), e);
                httpResponse.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, e.getMessage());
                return null;
            }
        }


        void doFilter(HttpServletRequest httpRequest, HttpServletResponse httpResponse)
                throws IOException, ServletException
        {
            final OAuthClient oAuthClient = authorizedClient(httpRequest, httpResponse);

            if (oAuthClient == null)
                return;

            if (!filters.isEmpty())
                filters.forEach(filter -> filter.doFilter(httpRequest, httpResponse, oAuthClient));
        }
        //endregion
    }

    //region Method filter
    public static class Post extends GenericMethodFilter
    {
        @Inject
        public Post(OAuthService oAuthService, Set<OAuthFilter> filters)
        {
            super(oAuthService, filters);
        }
    }

    public static class Get extends GenericMethodFilter
    {
        @Inject
        public Get(OAuthService oAuthService, Set<OAuthFilter> filters)
        {
            super(oAuthService, filters);
        }
    }

    public static class Put extends GenericMethodFilter
    {
        @Inject
        public Put(OAuthService oAuthService, Set<OAuthFilter> filters)
        {
            super(oAuthService, filters);
        }
    }

    public static class Patch extends GenericMethodFilter
    {
        @Inject
        public Patch(OAuthService oAuthService, Set<OAuthFilter> filters)
        {
            super(oAuthService, filters);
        }
    }

    public static class Delete extends GenericMethodFilter
    {
        @Inject
        public Delete(OAuthService oAuthService, Set<OAuthFilter> filters)
        {
            super(oAuthService, filters);
        }
    }
    //endregion
}
