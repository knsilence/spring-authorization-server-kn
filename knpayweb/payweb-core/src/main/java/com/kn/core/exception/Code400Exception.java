package com.kn.core.exception;


import com.kn.core.common.ApiStatus;

public class Code400Exception extends BaseException {
    private static final long serialVersionUID = 1L;

    public Code400Exception() {
        setCode(ApiStatus.CODE_400);
        setMsg(ApiStatus.CODE_400_MSG);
    }

    public Code400Exception(String msg) {
        setCode(ApiStatus.CODE_400);
        setMsg(msg);
    }
}
