package com.cryptopals.utils;

import java.util.ArrayList;

public class KeyValueList extends ArrayList<KeyValuePair<String, String>>
{
	private static final long serialVersionUID = 1L;
	
	public KeyValueList(String s)
	{
		super();
		parseFromString(s);
	}
	
	public KeyValueList() { super(); }

	public void parseFromString(String s)
	{
		boolean haveKey = false;
		String curKey = "";
		String curValue = "";
		for (int i = 0; i < s.length(); i++)
		{
			if(haveKey == false && s.charAt(i) == '=')  { haveKey = true; continue; }
			else if(s.charAt(i) == '&') 
			{
				this.add(new KeyValuePair<String, String>(curKey, curValue));
				curKey = "";
				curValue = "";
				haveKey = false;
				continue;
			}
			if(!haveKey) curKey += s.charAt(i);
			else curValue += s.charAt(i);
		}
		if(haveKey)
		{
			this.add(new KeyValuePair<String, String>(curKey, curValue));
		}
	}
	
	public void add(String k, String v)
	{
		add(new KeyValuePair<String, String>(k, v));
	}
	
	public String getValue(String k)
	{
		for(KeyValuePair<String, String> p: this)
		{
			if(p.getKey().equals(k)) return p.getValue();
		}
		return "";
	}
	
	public String encode()
	{
		String ret = "";
		for(KeyValuePair<String, String> k : this)
		{
			ret += k.getKey() + "=" + k.getValue() + "&";
		}
		return ret.substring(0, ret.length() - 1);
	}
	
	public String toString()
	{
		String ret = "{\n";
		for(KeyValuePair<String, String> k : this)
		{
			ret += "\t" + k.getKey() + ": '" + k.getValue() + "'\n";  
		}
		ret += "}";
		return ret;
	}
	
}
