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

public class OAuthBaseFilter
{
    private static final Logger logger = LoggerFactory.getLogger(OAuthBaseFilter.class);

    @Inject private OAuthService oAuthService;
    @Inject private Set<OAuthFilter> filters;

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

    //region Method filter
    class GenericMethodFilter implements Filter
    {
        @Override
        public void init(FilterConfig filterConfig) throws ServletException { }

        @Override
        public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain)
                throws IOException, ServletException
        {
            final HttpServletRequest httpRequest = (HttpServletRequest) servletRequest;
            final HttpServletResponse httpResponse = (HttpServletResponse) servletResponse;

            if (httpRequest.getMethod().equalsIgnoreCase(this.getClass().getName()))
                OAuthBaseFilter.this.doFilter(httpRequest, httpResponse);
            filterChain.doFilter(servletRequest, servletResponse);
        }

        @Override
        public void destroy() { }
    }
    public class Post extends GenericMethodFilter {}
    public class Get extends GenericMethodFilter {}
    public class Put extends GenericMethodFilter {}
    public class Patch extends GenericMethodFilter {}
    public class Delete extends GenericMethodFilter {}
    //endregion
}
