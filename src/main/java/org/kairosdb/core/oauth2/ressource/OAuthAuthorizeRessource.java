package org.kairosdb.core.oauth2.ressource;

import com.google.inject.Inject;
import org.kairosdb.core.oauth2.OAuthService;
import org.kairosdb.core.oauth2.client.OAuthClient;
import org.kairosdb.core.oauth2.exceptions.OAuthFlowException;
import org.kairosdb.core.oauth2.exceptions.OAuthWebException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;
import java.net.URI;
import java.net.URISyntaxException;

@Path("/api/oauth2")
public class OAuthAuthorizeRessource
{
    private final static Logger logger = LoggerFactory.getLogger(OAuthAuthorizeRessource.class);
    @Context
    private HttpServletRequest httpRequest;
    @Inject
    private OAuthService oAuthService;

    @GET
    @Path("authorize")
    public Response authorizeUser(@QueryParam("code") String code, @QueryParam("state") String state)
            throws URISyntaxException, OAuthFlowException
    {
        try
        {
            final OAuthService.OAuthPacket requestPacket = OAuthService.packetFrom(httpRequest, oAuthService.getCookieManager());
            final OAuthClient client = oAuthService.getClient(requestPacket);

            if (client == null || client.isAuthenticated())
                return Response.seeOther(URI.create("/")).build();

            OAuthService.OAuthPacket response = oAuthService.authorizeAuthentication(requestPacket, code, state);
            return response.toResponse((Response.ResponseBuilder) null).build();

        } catch (Exception e)
        {
            throw new OAuthWebException(Response.Status.INTERNAL_SERVER_ERROR, e.getMessage());
        }
    }
}
