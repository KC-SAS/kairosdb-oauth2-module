package org.kairosdb.core.oauth2.exceptions;

public class OAuthValidationException extends SecurityException
{
    private static final String INVALID_TOKEN = "Invalid internal token (%s -> %s), cookie can be usurped.";

    public OAuthValidationException(String validToken, String invalidToken)
    {
        super(String.format(INVALID_TOKEN, validToken, invalidToken));
    }
}
