package org.kairosdb.core.oauth2.filter;

import com.google.inject.Inject;
import org.kairosdb.core.oauth2.client.OAuthClient;
import org.kairosdb.core.oauth2.OAuthService;
import org.kairosdb.core.oauth2.exceptions.OAuthFlowException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;

public class OAuthFilter implements Filter
{
    private static final Logger logger = LoggerFactory.getLogger(OAuthFilter.class);
    @Inject
    private OAuthService oAuthService;

    private void authenticateClient(OAuthService.OAuthPacket requestPacket,
                                    HttpServletRequest httpRequest,
                                    HttpServletResponse httpResponse)
            throws URISyntaxException, IOException, OAuthFlowException
    {
        final OAuthService.OAuthPacket responsePacket = oAuthService.startAuthentication(requestPacket, new URI(httpRequest.getRequestURI()));
        logger.warn(String.format("'%s' not allowed to access to '%s'.", requestPacket.getRemoteAddr(), httpRequest.getRequestURI()));

        responsePacket.toResponse(httpResponse);
    }

    private boolean isAuthorized(HttpServletRequest httpRequest, HttpServletResponse httpResponse) throws IOException
    {
        try
        {
            URI redirectUri = new URI(oAuthService.getRedirectionUri());
            if (httpRequest.getRequestURI().equals(redirectUri.getPath()))
                return true;

            final OAuthService.OAuthPacket requestPacket = OAuthService.packetFrom(httpRequest, oAuthService.getCookieManager());
            final OAuthClient client = oAuthService.getClient(requestPacket);

            if (client != null && client.isAuthenticated())
                return true;

            if (client == null)
                logger.warn("User not found");
            else
                logger.warn("User name: " + client.getUserIdentifier());
            authenticateClient(requestPacket, httpRequest, httpResponse);
            return false;

        } catch (Exception e)
        {
            logger.error(e.getMessage(), e);
            httpResponse.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, e.getMessage());
            return false;
        }
    }


    @Override
    public void init(FilterConfig filterConfig) throws ServletException { }

    @Override
    public void destroy() { }


    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException
    {
        HttpServletRequest httpRequest = (HttpServletRequest) servletRequest;
        HttpServletResponse httpResponse = (HttpServletResponse) servletResponse;

        if (isAuthorized(httpRequest, httpResponse))
            filterChain.doFilter(servletRequest, servletResponse);
    }
}
