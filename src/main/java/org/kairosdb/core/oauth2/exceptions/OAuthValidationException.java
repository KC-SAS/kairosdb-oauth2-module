package org.kairosdb.core.oauth2.exceptions;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class OAuthValidationException extends SecurityException
{
    private static final String INVALID_TOKEN = "Invalid internal token (%s -> %s), cookie can be usurped.";

    public OAuthValidationException(String validToken, String invalidToken)
    {
        super(String.format(
                INVALID_TOKEN,
                new String(Base64.getEncoder().encode(validToken.getBytes(StandardCharsets.UTF_8))),
                new String(Base64.getEncoder().encode(invalidToken.getBytes(StandardCharsets.UTF_8)))
        ));
    }
}
