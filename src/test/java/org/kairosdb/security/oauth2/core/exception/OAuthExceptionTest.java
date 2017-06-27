package org.kairosdb.security.oauth2.core.exception;

import org.junit.Test;

import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

public class OAuthExceptionTest
{
    @Test(expected = OAuthConfigurationException.class)
    public void oAuthConfigurationException_fromString()
    {
        throw new OAuthConfigurationException("prefix");
    }

    @Test(expected = OAuthConfigurationException.class)
    public void oAuthConfigurationException_fromException()
    {
        throw new OAuthConfigurationException(new IllegalArgumentException("Illegal Argument"));
    }

    @Test(expected = OAuthFlowException.class)
    public void oAuthFlowException_fromString() throws OAuthFlowException
    {
        throw new OAuthFlowException("Exception");
    }

    @Test(expected = OAuthFlowException.class)
    public void oAuthFlowException_fromException() throws OAuthFlowException
    {
        throw new OAuthFlowException(new IllegalArgumentException("Illegal Argument"));
    }

    @Test(expected = OAuthValidationException.class)
    public void oAuthValidationException()
    {
        throw new OAuthValidationException();
    }

    @Test(expected = OAuthWebException.class)
    public void oAuthWebException()
    {
        throw new OAuthWebException(Response.Status.ACCEPTED, "Accepted", MediaType.TEXT_HTML_TYPE);
    }

    @Test(expected = OAuthWebException.class)
    public void oAuthWebException_withoutMediaType()
    {
        throw new OAuthWebException(Response.Status.ACCEPTED, "Accepted");
    }
}
