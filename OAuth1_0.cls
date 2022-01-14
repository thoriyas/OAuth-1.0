public class OAuth1_0 {
	
	private String token;
	private String tokenSecret;
	private Boolean isAccess = false;
	private String verifier;

	private String nonce;
	private String timestamp;
	private String signature;
	public static String consumerKey;
	public static String consumerSecret;

	private Map<String,String> parameters = new Map<String,String>();
	
	public String message { get; set; }

	public String callbackUrl {get; set; }
	
	public void setConsumerKey(String value) { consumerKey = value; }
	public void setConsumerSecret(String value) { consumerSecret = value; }
    
    public void doRequest(String consumerKey, String consumerSecret, String endPoint){
        consumerKey = leadSetting.Client_Key__c;
		    consumerSecret = leadSetting.Client_Secret__c;
       
        Http h = new Http();
        HttpRequest req = new HttpRequest();
        req.setMethod('GET');
        req.setEndpoint(lendPoint);
        req.setHeader('Accept-Encoding', 'gzip, deflate, br');
        req.setHeader('Accept', '*/*');
        
        sign(req);
        
        HTTPResponse resp = h.send(req);
        system.debug('+++++resp++'+resp);
        system.debug('+++++resp Body++'+resp.getBody()); 
        
    }
    
    
    
    private void refreshParameters() {
      parameters.clear();
          nonce     = EncodingUtil.convertToHex(Crypto.generateAesKey(128)).substring(0, 10);//String.valueOf(Crypto.getRandomLong());
          timestamp = String.valueOf(DateTime.now().getTime() / 1000);
      parameters.put('oauth_consumer_key',consumerKey);
      parameters.put('oauth_timestamp',timestamp);
      parameters.put('oauth_signature_method','HMAC-SHA1');
      parameters.put('oauth_nonce',nonce);
          parameters.put('oauth_version','1.0');

      //parameters.put('oauth_callback',callbackUrl);
	  }
    
    private Map<String,String> getUrlParams(String value) {
        Map<String,String> res = new Map<String,String>();
        if(value==null || value=='') {
            return res;
        }
        for(String s : value.split('&')) {
            System.debug('getUrlParams: '+s);
            List<String> kv = s.split('=');
            if(kv.size()>1) {
                // RFC 5849 section 3.4.1.3.1 and 3.4.1.3.2 specify that parameter names 
                // and values are decoded then encoded before being sorted and concatenated
                // Section 3.6 specifies that space must be encoded as %20 and not +
                String encName = EncodingUtil.urlEncode(EncodingUtil.urlDecode(kv[0], 'UTF-8'), 'UTF-8').replace('+','%20');
                String encValue = EncodingUtil.urlEncode(EncodingUtil.urlDecode(kv[1], 'UTF-8'), 'UTF-8').replace('+','%20');
                System.debug('getUrlParams:  -> '+encName+','+encValue);
                res.put(encName,encValue);
            }
        }
        return res;
    }

    private String createBaseString(Map<String,String> oauthParams, HttpRequest req) {
        Map<String,String> p = oauthParams.clone();
        if(req.getMethod().equalsIgnoreCase('post') && req.getBody()!=null && 
           req.getHeader('Content-Type')=='application/x-www-form-urlencoded') {
               p.putAll(getUrlParams(req.getBody()));
           }
        String host = req.getEndpoint();
        Integer n = host.indexOf('?');
        if(n>-1) {
            p.putAll(getUrlParams(host.substring(n+1)));
            host = host.substring(0,n);
        }
        List<String> keys = new List<String>();
        keys.addAll(p.keySet());
        keys.sort();
        String s = keys.get(0)+'='+p.get(keys.get(0));
        for(Integer i=1;i<keys.size();i++) {
            s = s + '&' + keys.get(i)+'='+p.get(keys.get(i));
        }
        
        // According to OAuth spec, host string should be lowercased, but Google and LinkedIn
        // both expect that case is preserved.
        return req.getMethod().toUpperCase()+ '&' + 
            EncodingUtil.urlEncode(host, 'UTF-8') + '&' +
            EncodingUtil.urlEncode(s, 'UTF-8');
    }
    
    public void sign(HttpRequest req) {
        nonce = String.valueOf(Crypto.getRandomLong());
        timestamp = String.valueOf(DateTime.now().getTime()/1000);
        
        refreshParameters();
        
        String s = createBaseString(parameters, req);
        
        System.debug('Signature base string: '+s);
        
        Blob sig = Crypto.generateMac('HmacSHA1', Blob.valueOf(s), 
                                      Blob.valueOf(consumerSecret+'&'+
                                                   (tokenSecret!=null ? tokenSecret : '')));
        signature = EncodingUtil.urlEncode(EncodingUtil.base64encode(sig), 'UTF-8');
        System.debug('Signature: '+signature);
        
        String header = 'OAuth ';
        for (String key : parameters.keySet()) {
            header = header + key + '="'+parameters.get(key)+'", ';
        }
        header = header + 'oauth_signature="'+signature+'"';
        System.debug('Authorization: '+header);
        req.setHeader('Authorization',header);
    }
}
