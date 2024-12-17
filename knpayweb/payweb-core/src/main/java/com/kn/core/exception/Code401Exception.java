package com.kn.core.exception;

import com.kn.core.common.ApiStatus;

public class Code401Exception extends BaseException {
    private static final long serialVersionUID = 1L;

    public Code401Exception() {
        setCode(ApiStatus.CODE_401);
        setMsg(ApiStatus.CODE_401_MSG);
    }

    public Code401Exception(String msg) {
        setCode(ApiStatus.CODE_401);
        setMsg(msg);
    }
}