package org.kairosdb.security.oauth2.cookie;

import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.kairosdb.security.oauth2.utils.HttpServletRequestImpl;
import org.kairosdb.security.oauth2.utils.HttpServletResponseImpl;
import org.kairosdb.security.oauth2.utils.ResponseBuilderImpl;

import javax.servlet.http.Cookie;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class SimpleCookieManagerTest
{
    private static final String cookie_name = "cookie_test";
    private static String internalToken;
    private static String encodedInternalToken;
    private static SimpleCookieManager cookieManager;

    @BeforeClass
    public static void setup()
    {
        cookieManager = new SimpleCookieManager(cookie_name);
        internalToken = String.valueOf(cookieManager.hashCode());
        encodedInternalToken = new String(Base64.getEncoder().encode(internalToken.getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    public void insertInternalToken_Servlet() throws Exception
    {
        HttpServletResponseImpl response = new HttpServletResponseImpl();
        cookieManager.insertInternalToken(response, internalToken);
        Assert.assertEquals(encodedInternalToken, response.getCookie().getValue());
    }

    @Test
    public void insertInternalToken_Response() throws Exception
    {
        ResponseBuilderImpl responseBuilder = new ResponseBuilderImpl();
        cookieManager.insertInternalToken(responseBuilder, internalToken);
        Assert.assertEquals(encodedInternalToken, responseBuilder.getCookie().getValue());
    }

    @Test
    public void extractInternalToken() throws Exception
    {
        HttpServletRequestImpl request = new HttpServletRequestImpl();
        Cookie cookie = new Cookie(cookie_name, encodedInternalToken);
        request.addCookie(cookie);

        Assert.assertEquals(internalToken, cookieManager.extractInternalToken(request));
    }

}