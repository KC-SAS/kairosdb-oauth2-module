package org.kairosdb.security.oauth2.core;

import org.junit.Assert;
import org.junit.Test;
import org.kairosdb.security.oauth2.core.exception.OAuthConfigurationException;
import org.kairosdb.security.oauth2.utils.HttpServletRequestImpl;
import org.kairosdb.security.oauth2.utils.HttpServletResponseImpl;
import org.kairosdb.security.oauth2.utils.OAuthCookieManagerImpl;

import java.net.URI;

import static org.kairosdb.security.oauth2.core.OAuthService.packetFrom;

public class OAuthServiceTest
{
    @Test(expected = OAuthConfigurationException.class)
    public void validateProperty() throws Exception
    {
        OAuthService.validateProperty(null, "");
    }

    @Test
    public void packetFrom_valid() throws Exception
    {
        final OAuthCookieManagerImpl oAuthCookieManager = new OAuthCookieManagerImpl();
        final HttpServletRequestImpl httpServletRequest = new HttpServletRequestImpl();
        final HttpServletResponseImpl httpServletResponse = new HttpServletResponseImpl();
        oAuthCookieManager.insertInternalToken(httpServletResponse, "token");
        httpServletRequest.addCookie(httpServletResponse.getCookie());
        httpServletRequest.setRequestURI("http://google.fr");
        httpServletRequest.setRemoteAddr("localhost");

        final OAuthService.OAuthPacket oAuthPacketValid = new OAuthService.OAuthPacket("localhost", new URI("http://google.fr"), "token", oAuthCookieManager);
        final OAuthService.OAuthPacket oAuthPacket = packetFrom(httpServletRequest, oAuthCookieManager);
        Assert.assertEquals(oAuthPacketValid, oAuthPacket);
    }

}