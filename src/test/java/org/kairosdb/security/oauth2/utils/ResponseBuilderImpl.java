package org.kairosdb.security.oauth2.utils;

import javax.ws.rs.core.*;
import java.net.URI;
import java.util.*;

public class ResponseBuilderImpl extends Response.ResponseBuilder
{
    private NewCookie cookies;
    private Map<String, String> headers = new HashMap<>();

    @Override
    public Response.ResponseBuilder cookie(NewCookie... newCookies)
    {
        this.cookies = newCookies[0];
        return this;
    }

    public NewCookie getCookie()
    {
        return cookies;
    }

    @Override
    public Response.ResponseBuilder header(String s, Object o)
    {
        headers.put(s, o.toString());
        return this;
    }

    public String getHeader(String name)
    {
        return headers.get(name);
    }

    @Override
    public Response.ResponseBuilder status(int i)
    {
        return this;
    }

    @Override
    public Response.ResponseBuilder location(URI uri)
    {
        return this;
    }

    //region Not implemented methods
    @Override
    public Response build()
    {
        return null;
    }

    @Override
    public Response.ResponseBuilder clone()
    {
        return null;
    }

    @Override
    public Response.ResponseBuilder entity(Object o)
    {
        return null;
    }

    @Override
    public Response.ResponseBuilder type(MediaType mediaType)
    {
        return null;
    }

    @Override
    public Response.ResponseBuilder type(String s)
    {
        return null;
    }

    @Override
    public Response.ResponseBuilder variant(Variant variant)
    {
        return null;
    }

    @Override
    public Response.ResponseBuilder variants(List<Variant> list)
    {
        return null;
    }

    @Override
    public Response.ResponseBuilder language(String s)
    {
        return null;
    }

    @Override
    public Response.ResponseBuilder language(Locale locale)
    {
        return null;
    }

    @Override
    public Response.ResponseBuilder contentLocation(URI uri)
    {
        return null;
    }

    @Override
    public Response.ResponseBuilder tag(EntityTag entityTag)
    {
        return null;
    }

    @Override
    public Response.ResponseBuilder tag(String s)
    {
        return null;
    }

    @Override
    public Response.ResponseBuilder lastModified(Date date)
    {
        return null;
    }

    @Override
    public Response.ResponseBuilder cacheControl(CacheControl cacheControl)
    {
        return null;
    }

    @Override
    public Response.ResponseBuilder expires(Date date)
    {
        return null;
    }
    //endregion
}
