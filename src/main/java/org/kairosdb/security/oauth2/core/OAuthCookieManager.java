package org.kairosdb.security.oauth2.core;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.core.Response;

public interface OAuthCookieManager
{
    /**
     * Insert a cookie with the internal token into the response
     *
     * @param response      response where we insert the token
     * @param internalToken internal token of the user
     * @return response with the token included
     */
    HttpServletResponse insertInternalToken(HttpServletResponse response, String internalToken);

    /**
     * Insert a cookie with the internal token into the response
     *
     * @param response      response where we insert the token
     * @param internalToken internal token of the user
     * @return response with the token included
     */
    Response.ResponseBuilder insertInternalToken(Response.ResponseBuilder response, String internalToken);

    /**
     * Extract the internal token from the request
     *
     * @param request request where the token was
     * @return internal token (or {@code null} if token not found)
     */
    String extractInternalToken(HttpServletRequest request);
}
