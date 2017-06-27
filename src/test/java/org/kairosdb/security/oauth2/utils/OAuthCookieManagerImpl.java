package org.kairosdb.security.oauth2.utils;

import org.kairosdb.security.oauth2.core.OAuthCookieManager;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.core.NewCookie;
import javax.ws.rs.core.Response;

public class OAuthCookieManagerImpl implements OAuthCookieManager
{
    public static final String COOKIE_NAME = "oauth_cookie";

    @Override
    public HttpServletResponse insertInternalToken(HttpServletResponse response, String internalToken)
    {
        response.addCookie(new Cookie(COOKIE_NAME, internalToken));
        return response;
    }

    @Override
    public Response.ResponseBuilder insertInternalToken(Response.ResponseBuilder response, String internalToken)
    {
        response.cookie(new NewCookie(COOKIE_NAME, internalToken));
        return response;
    }

    @Override
    public String extractInternalToken(HttpServletRequest request)
    {
        if (request.getCookies().length > 0)
            return request.getCookies()[0].getValue();
        return "";
    }
}
