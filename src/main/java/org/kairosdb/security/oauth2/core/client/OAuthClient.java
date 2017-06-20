package org.kairosdb.security.oauth2.core.client;

public interface OAuthClient
{
    /**
     * Return internal token of the current oauth client
     *
     * @return internal token
     */
    String getInternalToken();

    /**
     * Return access token of the current oauth client
     *
     * @return access token
     */
    String getAccessToken();

    /**
     * Return an <b>immutable</b> identifier of the current oauth client
     *
     * @return immutable identifier
     */
    String getUserIdentifier();

    /**
     * Return if the current client is authenticated
     *
     * @return {@code true} if is authenticated, else {@code false}
     */
    boolean isAuthenticated();

    /**
     * Return if the current client is obsolete
     *
     * @param currentTime current timestamp
     * @return {@code true} if is obsolete, else {@code false}
     */
    boolean isObsolete(long currentTime);

    /**
     * Compare two instance of OAuthClient
     *
     * @param anotherClient instance to be compared with
     *                      the current instance
     * @return diff between these instances
     */
    int compareTo(OAuthClient anotherClient);
}
