package sdk;

import com.alibaba.fastjson.JSONObject;
import org.apache.http.client.HttpClient;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.impl.client.HttpClientBuilder;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.math.ec.ECPoint;
import org.fisco.bcos.groupsig.app.ConfigParser;
import org.fisco.bcos.groupsig.app.RequestSigService;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.servlet.ModelAndView;
import sdk.Bean.Configuration;
import sdk.Bean.LoginInstance;
import sdk.Bean.LoginInstanceManager;
import sdk.Tools.Util;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;
import java.util.Date;
import java.util.UUID;

import org.fisco.bcos.groupsig.app.*;

public class UPPRESSOInstance {
    BigInteger bigIntP = new BigInteger(Configuration.hexP,16);
    //  BigInteger bigIntQ = new BigInteger(Configuration.hexQ,16);
    X9ECParameters ecp = SECNamedCurves.getByName("secp256k1");

    UPPRESSOToken UPPRESSOToken;

    /**
     * modified by Zhu Wentian
     * **/
    public void receiveCode(HttpServletRequest request, String body) throws Exception {
        JSONObject jsonRequestBody = JSONObject.parseObject(body);
        String authorizationCode = jsonRequestBody.getString("Code");
        String ID = null;
        Cookie[] cookies = request.getCookies();
        for (int i = 0; i < cookies.length; i++) {
            if (cookies[i].getName().equals("SSO_Session")) {
                ID = cookies[i].getValue();
            }
        }
        LoginInstance loginInstance = (LoginInstance) LoginInstanceManager.getByName(ID);
        String PID_RP = loginInstance.getPID_RP();

        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "authorization_code");
        form.add("code", authorizationCode);
        form.add("redirect_uri", "http://redirect.com");

        Date exp = new Date(System.currentTimeMillis() + (60 * 1000));
        Date now = new Date(System.currentTimeMillis());
        Algorithm algorithm = Algorithm.none();
        String token = JWT.create()
                .withIssuer(PID_RP)
                .withSubject(PID_RP)
                .withAudience("http://127.0.0.1:8080/openid-connect-server-webapp/")
                .withJWTId(UUID.randomUUID().toString())
                .withExpiresAt(exp)
                .withIssuedAt(now)
                .withNotBefore(now)
                .sign(algorithm);

        ConfigParser configObj = new ConfigParser("conf/conn.json");
        String url = "http://" + configObj.getConnIp() + ":" + configObj.getConnPort();
        RequestSigService sigServiceRequestor = new RequestSigService(url);
        SigStruct sigObj = new SigStruct();
        try {
            boolean ret = sigServiceRequestor.groupSig(sigObj, "group1", "member1", token);
            if (!ret) {
                System.out.println("GROUP SIG FAILED");
                return;
            }
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }

        String sig = sigObj.getSig();
        String jwtBear = token + sig;
        //String jwtBear = "eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJzdWIiOiIwNEEzRjlFMTM3MzQwMjM3OUUyMzhGRTY2NDdCRTM0QjZCODZCQzU3RDI2OEJCMDdFNTg3MEUwQjE0NUQ1RTJEODBFMTk3MUI0RThGNzk4NjBGRkJCRjg0MURBMkFBMEJFNkU4OUY4OTJCMzM0NzI0MDQxNkNDRTM5MzQyMTI4MTU3IiwiYXVkIjoiaHR0cDovLzEyNy4wLjAuMTo4MDgwL29wZW5pZC1jb25uZWN0LXNlcnZlci13ZWJhcHBhIiwiaXNzIjoiMDRBM0Y5RTEzNzM0MDIzNzlFMjM4RkU2NjQ3QkUzNEI2Qjg2QkM1N0QyNjhCQjA3RTU4NzBFMEIxNDVENUUyRDgwRTE5NzFCNEU4Rjc5ODYwRkZCQkY4NDFEQTJBQTBCRTZFODlGODkyQjMzNDcyNDA0MTZDQ0UzOTM0MjEyODE1NyIsImlhdCI6MTY2MzE0NTg0NX0.ewogICAiVDEiIDogIjExM2M2YjNjZDA1YzBhNzNhOGJlYjQzOTU3Njg0NDYzZGMwNTcwZDM0ZDZjM2E3MWE1ZTVmNmM0NTVjYjAxZjRmOTFhODVhMDQwZTQ5NTJhYmViOWQwNzM2ZjYwZGY1ZmJiZmI0MGQ4ZjBkOGMwZjBmYzkzZTkzMjIxMDEzZThlNDFjMyIsCiAgICJUMiIgOiAiMGNhMTM5OTU1MjYzMzU4MDhmMzkzZWE2YTJlNzU5ZTlmYTVhMzJmNTBlMGJiZTI4MTY2MjkzNWU1ODRiNTljYmFjMGE0YzBjZmI4MDE4NDM1YTczNjdjNDBkYTJjMWI4MjEzODc0MzUwOGRlNzY5ODViY2NhZTRiMDliZGYxMjM4NDlmIiwKICAgIlQzIiA6ICIwOTE0YTRiNDU0NjcyOWI3YjAxOTVjNjc3NjAwOWM4NjZhNTFlYTY1ZmQ2ZmU5YzM1OWI0NGMxMjI3N2U5MWY5NjQwOWU2ZjgyN2RlMzBkYWVmMmM1YzRlOWY5ZTQ3YThlNmUzMDVkNWM2OWYxZDU5YTI3YmQxYjg2MGY5ZjhjNzM3NzQiLAogICAiYyIgOiAiN2MwYjViZWU4ZTAxOTA2MGIzOGViMDc1ZjBjNmYyMmFhZTMwMDJjNWE4ODRiNDY1ZDExYTY2YmRjMzk2Mjg4OCIsCiAgICJyYWxwaGEiIDogIjAyZTViZmJkMzJlZWViOWJlMDk3ZTcyNTczYjI4ZTFkZTE5NzVhYTZmNzlkY2UxMGQyZmQ4OTFjZjAxNDk3ZjUiLAogICAicmJldGEiIDogIjdkMmJkYmY5MWJkM2I3MmYxN2UyYzY3ZDA0ZjE1ODM3OTA5ZjAyOWNlOWFlZTYwYzdiNTdhMTU4YTcwN2RjNjEiLAogICAicmRlbHRhMSIgOiAiMDk4NDNiYzYyZGNjZjQ3MDQwOTlkODZkOWE0NmU3ZmU3OWFiNmFhZGM0MjZlYzk5ZDkzYjk5NzVkYTQ4ZDc4MCIsCiAgICJyZGVsdGEyIiA6ICI0YWI4ZDQ0NjgzMmQxZWE0NjRiOTgwMmIzMDMwZjhkNGFlOWNlZmM1YzkwYTRjZTIxNzg2NjhmYzQ3OGJlZTViIiwKICAgInJ4IiA6ICI2M2JmMzkzMzgyOGZmZTg4Mzk2MGE1ZjIwODY0NGU5OTI4MTFjNmUwY2Y5MzAzZGJkYWJkZDkzN2U5YjZjZGE3Igp9Cg==";

        form.add("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
        form.add("client_assertion", jwtBear);

        HttpClient httpClient = HttpClientBuilder.create()
                .useSystemProperties()
                .setDefaultRequestConfig(RequestConfig.custom()
                        .setSocketTimeout(30000)
                        .build())
                .build();

        HttpComponentsClientHttpRequestFactory factory = new HttpComponentsClientHttpRequestFactory(httpClient);
        RestTemplate restTemplate = new RestTemplate(factory);

        String jsonString = null;
        try {
            jsonString = restTemplate.postForObject("http://127.0.0.1:8080/openid-connect-server-webapp/token", form, String.class);
        } catch (RestClientException e) {
            System.out.println(e.getMessage());
        }
        JSONObject getToken = JSONObject.parseObject(jsonString);
        String id_token = getToken.getString("id_token");
        String myBody = "{\"Token\":\"" + id_token + "\"}";
        receiveToken(request, myBody);
    }

    public void receiveToken(HttpServletRequest request, String body) {
        JSONObject jsonRequestBody = JSONObject.parseObject(body);
        String id_token = jsonRequestBody.getString("Token");
        String ID = null;
        Cookie[] cookies = request.getCookies();
        for (int i = 0; i < cookies.length; i++) {
            if (cookies[i].getName().equals("SSO_Session")) {
                ID = cookies[i].getValue();
            }
        }
        LoginInstance loginInstance = (LoginInstance) LoginInstanceManager.getByName(ID);
        DecodedJWT token = decodeToken(id_token);
        UPPRESSOToken = new UPPRESSOToken();
        if(token != null) {
            if(token.getAudience().contains(loginInstance.getPID_RP())){
                UPPRESSOToken.setValid(true);
            }else {
                UPPRESSOToken.setValid(false);
            }
            BigInteger temp[] = ExtendEculid(new BigInteger(loginInstance.getT(), 16), ecp.getN());
            BigInteger _result = temp[1];
            org.bouncycastle.math.ec.ECPoint pointPUID = ecp.getCurve().decodePoint(Util.hexString2Bytes(token.getSubject()));
            ECPoint pointAccount = pointPUID.multiply(_result);
            String account = Util.bytes2HexString(pointAccount.getEncoded(false));
            UPPRESSOToken.init(token, account);
        }else {
            UPPRESSOToken.setValid(false);
        }
    }

    public BigInteger[] ExtendEculid(BigInteger a, BigInteger b)
    {
        BigInteger x,  y;
        if (b.compareTo(new BigInteger("0"))==0)
        {
            x = new BigInteger("1");
            y = new BigInteger("0");
            BigInteger[] t = new BigInteger[3];
            t[0] = a; t[1] = x; t[2] = y;
            return t;
        }
        BigInteger[] t = ExtendEculid(b, a.mod(b));
        BigInteger result = t[0];
        x = t[1];
        y = t[2];
        BigInteger temp = x;
        x = y;
        y = temp.subtract(a.divide(b).multiply(y));
        BigInteger[] t1 = new BigInteger[3];
        t1[0] = result; t1[1] = x; t1[2] = y;
        return t1;
    }

    DecodedJWT decodeToken(String token){
        String estr = Util.bytes2HexString(Base64.getUrlDecoder().decode(Configuration.PK_IDP.e));
        String nstr = Util.bytes2HexString(Base64.getUrlDecoder().decode(Configuration.PK_IDP.n));
        RSAPublicKeySpec keySpec = new RSAPublicKeySpec(new BigInteger(nstr, 16), new BigInteger(estr, 16));
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            RSAPublicKey publicKey = (RSAPublicKey) keyFactory.generatePublic(keySpec);
            Algorithm algorithm = Algorithm.RSA256(publicKey, null);
            JWTVerifier verifier = JWT.require(algorithm)
                    .build();
            DecodedJWT jwt = verifier.verify(token);
            return jwt;
        } catch (JWTVerificationException exception){
            //Invalid signature/claims
            return null;
        } catch (NoSuchAlgorithmException e1) {
            e1.printStackTrace();
            return null;
        } catch (InvalidKeySpecException e1) {
            e1.printStackTrace();
            return null;
        }
    }

    public UPPRESSOToken getToken() {
        return UPPRESSOToken;
    }

    public ModelAndView getInit() {
        ModelAndView mv = new ModelAndView();
        mv.setViewName("script");
        return mv;
    }
}
