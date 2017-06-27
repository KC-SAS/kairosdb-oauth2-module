package org.kairosdb.security.oauth2.utils;

import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

public class PropertiesImpl extends Properties
{
    private Map<String, String> map = new HashMap<>();

    public void addProperty(String key, String value)
    {
        map.put(key, value);
    }

    @Override
    public String getProperty(String key)
    {
        return map.get(key);
    }
}
