package org.kairosdb.security.oauth2.core.exception;

import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

public class OAuthWebException extends WebApplicationException
{
    public OAuthWebException(Response.Status status, String message)
    {
        super(Response
                .status(status)
                .entity(message)
                .type(MediaType.TEXT_PLAIN)
                .build()
        );
    }
}
