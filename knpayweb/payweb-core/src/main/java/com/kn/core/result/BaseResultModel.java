package com.kn.core.result;


import com.kn.core.common.ApiStatus;
import org.apache.commons.lang3.StringUtils;

public class BaseResultModel {

    /**
     * 标识
     */
    protected String code = ApiStatus.CODE_200;

    /**
     * 信息
     */
    protected String msg = ApiStatus.CODE_200_MSG;


    public String getCode() {
        return code;
    }


    public void setCode(String code) {
        this.code = code;
    }


    public String getMsg() {
        if (StringUtils.isEmpty(msg)) {
            return "";
        }
        String valmsg = null;
        if (msg.equals(ApiStatus.CODE_200_MSG)) {
            valmsg = ApiStatus.CODE_200_MSG;
        } else if (msg.equals(ApiStatus.CODE_500_MSG)) {
            valmsg = ApiStatus.CODE_500_MSG;
        }
        return msg;
    }


    public void setMsg(String msg) {
        this.msg = msg;
    }


}
