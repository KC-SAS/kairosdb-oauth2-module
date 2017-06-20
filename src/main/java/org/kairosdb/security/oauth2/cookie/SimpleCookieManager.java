package org.kairosdb.security.oauth2.cookie;

import org.kairosdb.security.oauth2.core.OAuthCookieManager;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.core.NewCookie;
import javax.ws.rs.core.Response;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;

public class SimpleCookieManager implements OAuthCookieManager
{
    private final static String COOKIE_NAME = "oauthToken";

    @Override
    public HttpServletResponse insertInternalToken(HttpServletResponse response, String internalToken)
    {
        String encodedInternalToken = new String(Base64.getEncoder().encode(internalToken.getBytes(StandardCharsets.UTF_8)));
        Cookie cookie = new Cookie(COOKIE_NAME, encodedInternalToken);
        cookie.setPath("/");
        cookie.setSecure(false);
        response.addCookie(cookie);
        return response;
    }

    @Override
    public Response.ResponseBuilder insertInternalToken(Response.ResponseBuilder response, String internalToken)
    {
        String encodedInternalToken = new String(Base64.getEncoder().encode(internalToken.getBytes(StandardCharsets.UTF_8)));
        response.cookie(new NewCookie(
                COOKIE_NAME, encodedInternalToken,
                "/", null,
                null, -1,
                false
        ));
        return response;
    }

    @Override
    public String extractInternalToken(HttpServletRequest request)
    {
        Cookie[] cookies = request.getCookies();

        Cookie oauthToken = Arrays.stream(cookies)
                .filter(cookie -> cookie.getName().equalsIgnoreCase(COOKIE_NAME))
                .findFirst()
                .orElse(null);

        if (oauthToken == null)
            return null;

        return new String(Base64.getDecoder().decode(oauthToken.getValue().getBytes(StandardCharsets.UTF_8)));
    }
}
