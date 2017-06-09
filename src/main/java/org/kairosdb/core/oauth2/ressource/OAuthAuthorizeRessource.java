package org.kairosdb.core.oauth2.ressource;

import com.google.inject.Inject;
import org.kairosdb.core.oauth2.client.OAuthClient;
import org.kairosdb.core.oauth2.OAuthService;
import org.kairosdb.core.oauth2.exceptions.OAuthFlowException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;
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
        final OAuthService.OAuthPacket requestPacket = OAuthService.packetFrom(httpRequest, oAuthService.getCookieManager());
        final OAuthClient client = oAuthService.getClient(requestPacket);

        if (client == null)
        {
            logger.error("Unexpected client here (Need more info)");
            return Response.status(Response.Status.BAD_REQUEST).entity("Unexpected client here (Need more info)").build();
        }
        if (client.isAuthenticated())
        {
            logger.warn("Already connected .... Why are you here ?");
            return Response.status(Response.Status.BAD_REQUEST).entity("Already connected .... Why are you here ?").build();
        }

        OAuthService.OAuthPacket response = oAuthService.authorizeAuthentication(requestPacket, code, state);
        Response _response = response.toResponse((Response.ResponseBuilder)null).build();
        return response.toResponse((Response.ResponseBuilder) null).build();
    }
}
