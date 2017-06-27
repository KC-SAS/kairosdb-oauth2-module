package org.kairosdb.security.oauth2.core;

import com.google.inject.Inject;
import com.google.inject.name.Named;
import org.kairosdb.security.auth.AuthenticationFilter;
import org.kairosdb.security.auth.core.exception.UnauthorizedClientResponse;
import org.kairosdb.security.oauth2.core.client.OAuthClient;
import org.kairosdb.security.oauth2.core.client.OAuthenticatedClient;
import org.kairosdb.security.oauth2.core.exception.OAuthFlowException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Properties;
import java.util.Set;

public class OAuthFilter implements AuthenticationFilter
{
    private static final Logger logger = LoggerFactory.getLogger(OAuthFilter.class);

    private boolean pluginsConfigured;
    private final Properties properties;
    private final OAuthService oAuthService;
    private final Set<OAuthPlugin> plugins;
    private final int responseWeight;

    @Inject
    public OAuthFilter(Properties properties,
                       OAuthService oAuthService,
                       Set<OAuthPlugin> plugins,
                       @Named("response_weight") int responseWeight)
    {
        this.properties = properties;
        this.oAuthService = oAuthService;
        this.plugins = plugins;
        this.responseWeight = responseWeight;
    }

    @Override
    public boolean tryAuthentication(HttpServletRequest httpRequest) throws UnauthorizedClientResponse
    {
        if (!pluginsConfigured)
            plugins.forEach(p -> p.configure(properties));
        pluginsConfigured = true;

        final OAuthClient oAuthClient = authorizedClient(httpRequest);
        if (oAuthClient == null)
            return false;

        for (OAuthPlugin plugin : plugins)
            if (!plugin.isAllowed((OAuthenticatedClient) oAuthClient, httpRequest))
                return false;
        return true;
    }

    private OAuthClient authorizedClient(HttpServletRequest httpRequest) throws UnauthorizedClientResponse
    {
        try
        {
            final URI redirectUri = new URI(oAuthService.getRedirectionUri());
            if (httpRequest.getRequestURI().equals(redirectUri.getPath()))
                return null;

            final OAuthService.OAuthPacket requestPacket = OAuthService
                    .packetFrom(httpRequest, oAuthService.getCookieManager());
            final OAuthClient client = oAuthService.getClient(requestPacket);

            if (client != null && client.isAuthenticated())
                return client;

            authenticateClient(requestPacket, httpRequest);
            return null;

        } catch (UnauthorizedClientResponse unauthorizedClient)
        {
            throw unauthorizedClient;
        } catch (Exception e)
        {
            logger.error(e.getMessage(), e);
            throw new UnauthorizedClientResponse(responseWeight,
                    response -> response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, e.getMessage())
            );
        }
    }

    private void authenticateClient(OAuthService.OAuthPacket requestPacket, HttpServletRequest httpRequest)
            throws URISyntaxException, UnauthorizedClientResponse, OAuthFlowException
    {
        final String requestUri = httpRequest.getRequestURI();
        logger.warn(String.format("'%s' not allowed to access to '%s'.", requestPacket.getRemoteAddr(), requestUri));

        final OAuthService.OAuthPacket responsePacket;
        responsePacket = oAuthService.startAuthentication(requestPacket, new URI(requestUri));

        throw new UnauthorizedClientResponse(responseWeight, responsePacket::toResponse);
    }
}
