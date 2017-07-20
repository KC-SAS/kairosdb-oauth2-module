package org.kairosdb.security.oauth2.core;

import org.junit.Assert;
import org.junit.Test;
import org.kairosdb.security.auth.core.exception.UnauthorizedClientResponse;
import org.kairosdb.security.oauth2.core.client.OAuthClient;
import org.kairosdb.security.oauth2.core.exception.OAuthFlowException;
import org.kairosdb.security.oauth2.utils.*;

import java.io.IOException;
import java.net.URISyntaxException;

import static org.kairosdb.security.oauth2.core.OAuthService.packetFrom;

public class OAuthFilterTest
{
    @Test
    public void tryAuthentication_unauthorized() throws IOException, URISyntaxException
    {
        final PropertiesImpl properties = new PropertiesImpl();
        properties.addProperty("kairosdb.security.oauth2.clientId", "aaa");
        properties.addProperty("kairosdb.security.oauth2.clientSecret", "bbb");
        properties.addProperty("kairosdb.security.oauth2.redirectionUri", "http://google.fr");

        final OAuthProvider oAuthProvider = new OAuthProviderImpl();
        final OAuthCookieManager oAuthCookieManager = new OAuthCookieManagerImpl();
        final OAuthService oAuthService = new OAuthService(oAuthProvider, oAuthCookieManager, properties);
        final OAuthFilter oAuthFilter = new OAuthFilter(oAuthService, 0);

        final HttpServletRequestImpl httpServletRequest = new HttpServletRequestImpl();
        final HttpServletResponseImpl httpServletResponse = new HttpServletResponseImpl();
        httpServletRequest.setRequestURI("localhost");

        try
        {
            oAuthFilter.tryAuthentication(httpServletRequest);
        } catch (UnauthorizedClientResponse response)
        {
            response.sendResponse(httpServletResponse);
        }

        httpServletRequest.addCookie(httpServletResponse.getCookie());
        final OAuthService.OAuthPacket oAuthPacket = packetFrom(httpServletRequest, oAuthCookieManager);

        final OAuthClient oAuthClient = oAuthService.getClient(oAuthPacket);
        Assert.assertNotNull("OAuthClient not found", oAuthClient);
        Assert.assertFalse("OAuthClient must be not authenticated", oAuthClient.isAuthenticated());
    }

    @Test
    public void tryAuthentication_failure() throws IOException, URISyntaxException
    {
        final PropertiesImpl properties = new PropertiesImpl();
        properties.addProperty("kairosdb.security.oauth2.clientId", "aaa");
        properties.addProperty("kairosdb.security.oauth2.clientSecret", "bbb");
        properties.addProperty("kairosdb.security.oauth2.redirectionUri", "http://google.fr");

        final OAuthProvider oAuthProvider = new OAuthProviderImpl();
        final OAuthCookieManager oAuthCookieManager = new OAuthCookieManagerImpl();
        final OAuthService oAuthService = new OAuthService(oAuthProvider, oAuthCookieManager, properties);
        final OAuthFilter oAuthFilter = new OAuthFilter(oAuthService, 0);

        try
        {
            oAuthFilter.tryAuthentication(null);
        } catch (UnauthorizedClientResponse response)
        {
            Assert.assertEquals(NullPointerException.class, response.getCause().getClass());
        }
    }

    @Test
    public void tryAuthentication() throws IOException, URISyntaxException, OAuthFlowException, UnauthorizedClientResponse
    {
        final PropertiesImpl properties = new PropertiesImpl();
        properties.addProperty("kairosdb.security.oauth2.clientId", "aaa");
        properties.addProperty("kairosdb.security.oauth2.clientSecret", "bbb");
        properties.addProperty("kairosdb.security.oauth2.redirectionUri", "http://google.fr");

        final OAuthProvider oAuthProvider = new OAuthProviderImpl();
        final OAuthCookieManager oAuthCookieManager = new OAuthCookieManagerImpl();
        final OAuthService oAuthService = new OAuthService(oAuthProvider, oAuthCookieManager, properties);
        final OAuthFilter oAuthFilter = new OAuthFilter(oAuthService, 0);

        HttpServletRequestImpl httpServletRequest = new HttpServletRequestImpl();
        HttpServletResponseImpl httpServletResponse = new HttpServletResponseImpl();
        httpServletRequest.setRequestURI("localhost");
        httpServletRequest.setRemoteAddr("localhost");

        try
        {
            oAuthFilter.tryAuthentication(httpServletRequest);
        } catch (UnauthorizedClientResponse response)
        {
            response.sendResponse(httpServletResponse);
        }

        httpServletRequest.addCookie(httpServletResponse.getCookie());
        OAuthService.OAuthPacket oAuthPacket = packetFrom(httpServletRequest, oAuthCookieManager);
        oAuthPacket = oAuthService.authorizeAuthentication(oAuthPacket, "", "");

        httpServletResponse = (HttpServletResponseImpl) oAuthPacket.toResponse(httpServletResponse);
        httpServletRequest.addCookie(httpServletResponse.getCookie());

        final OAuthClient oAuthClient = oAuthService.getClient(packetFrom(httpServletRequest, oAuthCookieManager));
        Assert.assertNotNull("OAuthClient not found", oAuthClient);
        Assert.assertTrue("OAuthClient must be authenticated", oAuthClient.isAuthenticated());
        Assert.assertTrue(oAuthFilter.tryAuthentication(httpServletRequest).isAllowed());
    }

}