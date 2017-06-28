package org.kairosdb.security.oauth2.core.exception;

public class OAuthConfigurationException extends IllegalArgumentException
{
    private static final String INVALID_PROPERTY_FILE = "Invalid property file: property '%s' need to be set for OAuth2 features.";
    private static final String INTERNAL_EXCEPTION = "'%s': %s";

    public OAuthConfigurationException(String propertyPrefix)
    {
        super(String.format(INVALID_PROPERTY_FILE, propertyPrefix));
    }

    public OAuthConfigurationException(Throwable cause)
    {
        super(String.format(INTERNAL_EXCEPTION, cause.getClass().getName(), cause.getMessage()), cause);
    }
}
