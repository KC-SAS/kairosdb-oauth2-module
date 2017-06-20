package org.kairosdb.security.oauth2.core.exception;

public class OAuthValidationException extends SecurityException
{
    private static final String INVALID_TOKEN = "Invalid internal token, cookie can be usurped.";

    public OAuthValidationException()
    {
        super(INVALID_TOKEN);
    }
}
