package org.kairosdb.security.oauth2.core;

import com.google.inject.Inject;
import com.google.inject.name.Named;
import org.kairosdb.security.auth.authenticator.AuthenticatorFilter;
import org.kairosdb.security.auth.authenticator.AuthenticatorResult;
import org.kairosdb.security.auth.core.exception.UnauthorizedClientResponse;
import org.kairosdb.security.oauth2.core.OAuthService.OAuthPacket;
import org.kairosdb.security.oauth2.core.client.OAuthClient;
import org.kairosdb.security.oauth2.core.exception.OAuthFlowException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServletRequest;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Optional;

import static javax.servlet.http.HttpServletResponse.SC_INTERNAL_SERVER_ERROR;

public class OAuthFilter implements AuthenticatorFilter
{
    private static final Logger logger = LoggerFactory.getLogger(OAuthFilter.class);

    private final OAuthService oAuthService;
    private final int responseWeight;

    @Inject
    OAuthFilter(OAuthService oAuthService, @Named("response_weight") int responseWeight)
    {
        this.oAuthService = oAuthService;
        this.responseWeight = responseWeight;
    }

    @Override
    public AuthenticatorResult tryAuthentication(HttpServletRequest httpRequest) throws UnauthorizedClientResponse
    {
        final Optional<OAuthClient> oAuthClient = authorizedClient(httpRequest);

        if (oAuthClient.isPresent())
            return AuthenticatorResult.allow(oAuthClient.get().getUserIdentifier(), getClass());
        return AuthenticatorResult.deny(getClass());
    }

    private Optional<OAuthClient> authorizedClient(HttpServletRequest httpRequest) throws UnauthorizedClientResponse
    {
        try
        {
            final OAuthPacket requestPacket = OAuthService.packetFrom(httpRequest, oAuthService.getCookieManager());
            final OAuthClient client = oAuthService.getClient(requestPacket);

            if (client != null && client.isAuthenticated())
                return Optional.of(client);

            authenticateClient(requestPacket, httpRequest);
            return Optional.empty();

        } catch (UnauthorizedClientResponse unauthorizedClient)
        {
            throw unauthorizedClient;
        } catch (Exception exception)
        {
            logger.error(exception.getMessage(), exception);
            throw new UnauthorizedClientResponse(
                    responseWeight,
                    response -> response.sendError(SC_INTERNAL_SERVER_ERROR, exception.getMessage()),
                    exception
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
