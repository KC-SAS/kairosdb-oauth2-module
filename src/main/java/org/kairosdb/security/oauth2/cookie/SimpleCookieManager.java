package org.kairosdb.security.oauth2.cookie;

import com.google.inject.Inject;
import com.google.inject.name.Named;
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
    private final static Base64.Encoder base64encoder = Base64.getEncoder();
    private final static Base64.Decoder base64decoder = Base64.getDecoder();
    private final String cookie_name;

    @Inject
    SimpleCookieManager(@Named("cookie_name") String cookie_name)
    {
        this.cookie_name = cookie_name;
    }

    public HttpServletResponse insertInternalToken(HttpServletResponse response, String internalToken)
    {
        final String encodedInternalToken = new String(base64encoder.encode(internalToken.getBytes(StandardCharsets.UTF_8)));
        final Cookie cookie = new Cookie(cookie_name, encodedInternalToken);

        cookie.setPath("/");
        cookie.setSecure(false);
        response.addCookie(cookie);
        return response;
    }

    @Override
    public Response.ResponseBuilder insertInternalToken(Response.ResponseBuilder response, String internalToken)
    {
        final String encodedInternalToken = new String(base64encoder.encode(internalToken.getBytes(StandardCharsets.UTF_8)));

        response.cookie(new NewCookie(
                cookie_name, encodedInternalToken,
                "/", null,
                null, -1,
                false
        ));
        return response;
    }

    @Override
    public String extractInternalToken(HttpServletRequest request)
    {
        final Cookie[] cookies = request.getCookies();

        Cookie oauthToken = Arrays.stream(cookies)
                .filter(cookie -> cookie.getName().equalsIgnoreCase(cookie_name))
                .findFirst()
                .orElse(null);

        if (oauthToken == null)
            return null;

        return new String(base64decoder.decode(oauthToken.getValue().getBytes(StandardCharsets.UTF_8)));
    }
}
