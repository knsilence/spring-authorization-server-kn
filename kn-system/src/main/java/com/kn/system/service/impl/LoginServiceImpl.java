package com.kn.system.service.impl;

import com.kn.core.common.GrantTypes;
import com.kn.core.common.Scopes;
import com.kn.core.common.TokenInfo;
import com.kn.system.client.AuthClient;
import com.kn.system.service.LoginService;
import jakarta.annotation.Resource;
import jakarta.transaction.Transactional;
import org.springframework.stereotype.Service;

import java.util.Calendar;
import java.util.Date;

import static com.kn.core.common.Scopes.SCOPE_TYPE_OPENID_WRITE;

@Service
@Transactional
public class LoginServiceImpl implements LoginService {

    @Resource
    private AuthClient authClient;


    private static final String public_key = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCKNKMOeTlnDG/vJCQ6yBdJWppp1BKuQRCr/ugEPpsE3EK0Ia1dEVrI3g9E+xNbsi26AsLJT8jn1UdIBfbz2GUGm31F7enTa+HNPstLds/bU89VKP1Q4osEdtU8p8CbR7pV0dDzFgCSnW2fVajxjuXP4FzpArnQlQ1nfFGXgDQ/LQIDAQAB";

    private static final String private_key = "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAPAm87Uu4THXrPLEoXsZQIzqIMDKjDQu8KhXBnuGasqfUT1m8gHs2wx4FM5G+DVR4OxwXAp3sCr4C3LzFwz4e7smhbBHjGuSzZ2vwjL+YNA0FPP1tyR2dBMkx9BWKX1MsHY0CTTZzboVCQwBkAVkYWtpHoilljIunCtINPFZCXRLAgMBAAECgYAeIu04rTzc9IaYt9HXMPM3m8E8yvjZgD3QCje0iZ4zdixg4F8knF9dYGD6r8+XCq2HTjmmpfVpYajiJceckj7Ic8xYRO0U5CRBNoYqUi0m7NpoY17AEAuA3YIPohEfioyv03Y8wHEq9kLbloLsTXlRsFBlpe0RGc8iHHhrO5ZxyQJBAPHpGUuBir1xnPxid4ncEluBswi0U5n3qFcud5s0esH4sUq8WP8MU53yTIXktOaR/4Hf3S+cu7IL26up2N6y3FkCQQD+I6KyGmVdBSKEe9cbUp4Vyw2SaMg8IRSqwkpxoKvJ38sB+4qNtifelClKW3Y/WTwSQr5VwCKQlPuNi0QD2vFDAkBDCxoijfVYiYs7e0Kr510DFU/8ApYE3tk9yDgHwKSg636fOtHjZZQq+wLwPLFSEXZhlRxk3Kg8MQMhcUIUfjeJAkBwb820ZI9CB1qNKMkzkmrUk4COrQMh7zTYk5siCIbYisWjO+nB5rxe8kgOWMbJIi68mYDiKV5hfziIF/xghEZHAkEAydE/wjPo6KD5zydnkR3gCvYcyeOrSDMHFQYuE8Aqmi9bH7cTKHMZTG/cCpS53auCZMWCmzHZxJsIauf1Y+W3Lw==";

    @Override
    public TokenInfo passwordLogin(String username,String password, String basicAuth) {
/*        String username = null;
        String password = null;
        Long timestamp = null;
        try {
            String loginStr = CreateSecretKey.decryptByPrivateKey(secretData, private_key);
            JSONObject jsonobj = JSONObject.fromObject(loginStr);
            username = jsonobj.getString("username");
            password = jsonobj.getString("password");
            timestamp = jsonobj.getLong("timestamp");
        } catch (Exception e) {
      throw new Code500Exception("secretKey错误");
        }
        if (StringUtils.isEmpty(username) || StringUtils.isEmpty(password)) {
            throw new Code500Exception("账号或密码为空");
        }*/

        //再验证时间戳
/*        Calendar logincal = Calendar.getInstance();
        Calendar nowcal = Calendar.getInstance();
        nowcal.setTime(new Date());
        logincal.setTimeInMillis(timestamp);
        Long mintime = nowcal.getTimeInMillis() - logincal.getTimeInMillis();
        if (mintime >= 300 * 1000) {
            throw new Code500Exception("时间太长");
        }*/
        try {
            TokenInfo token = this.authClient.webPassword(GrantTypes.GRANT_TYPE_PASSWORD_CODE, Scopes.SCOPE_TYPE_OPENID_WRITE, username, password,  basicAuth);
            return token;
        } catch (Exception e) {
            throw e;
        }
    }

    @Override
    public TokenInfo emailLogin(String emailName, String emailCode, String basicAuth) {

        try {
            TokenInfo token = this.authClient.webEmail(GrantTypes.GRANT_TYPE_EMAIL_CODE, Scopes.SCOPE_TYPE_OPENID_WRITE, emailName, emailCode,  basicAuth);
            return token;
        } catch (Exception e) {
            throw e;
        }
    }
}
