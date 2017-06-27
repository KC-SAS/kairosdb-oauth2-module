package org.kairosdb.security.oauth2.core;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.kairosdb.security.oauth2.utils.HttpServletResponseImpl;
import org.kairosdb.security.oauth2.utils.OAuthCookieManagerImpl;
import org.kairosdb.security.oauth2.utils.ResponseBuilderImpl;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.Map;

public class OAuthPacketTest
{
    private static final String remoteAddr = "127.0.0.1";
    private static final String internalToken = "e6f268b1-4f09-4370-857f-618fdf82067a";
    private static final OAuthCookieManagerImpl cookieManager = new OAuthCookieManagerImpl();
    private static OAuthService.OAuthPacket oAuthPacket;

    @Before
    public void setupTest() throws URISyntaxException
    {
        oAuthPacket = new OAuthService.OAuthPacket(remoteAddr, new URI("http://google.fr"), internalToken, cookieManager);
    }

    @Test
    public void setHeaders() throws IOException
    {
        final HttpServletResponseImpl servletResponse = new HttpServletResponseImpl();
        final ResponseBuilderImpl responseBuilder = new ResponseBuilderImpl();
        final Map<String, String> headers = new HashMap<>();
        headers.put("Key", "Value");

        oAuthPacket.setHeaders(headers);
        oAuthPacket.toResponse(servletResponse);
        oAuthPacket.toResponse(responseBuilder);

        Assert.assertEquals("Value", servletResponse.getHeader("Key"));
        Assert.assertEquals("Value", responseBuilder.getHeader("Key"));
    }

    @Test
    public void getRemoteAddr()
    {
        Assert.assertEquals(remoteAddr, oAuthPacket.getRemoteAddr());
    }

    @Test
    public void getRedirectUri() throws URISyntaxException
    {
        Assert.assertEquals(new URI("http://google.fr").toASCIIString(), oAuthPacket.getRedirectUri().toASCIIString());
    }
}