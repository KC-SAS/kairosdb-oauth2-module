package org.kairosdb.security.oauth2.core.exception;


public class OAuthFlowException extends Exception
{
    private static final String INTERRUPTED_FLOW = "Interrupted OAuth flow: %s";
    private static final String INTERNAL_EXCEPTION = "Interrupted OAuth flow by '%s': %s";

    public OAuthFlowException(String message)
    {
        super(String.format(INTERRUPTED_FLOW, message));
    }

    public OAuthFlowException(Exception e)
    {
        super(String.format(INTERNAL_EXCEPTION, e.getClass().getName(), e.getMessage()));
    }
}
