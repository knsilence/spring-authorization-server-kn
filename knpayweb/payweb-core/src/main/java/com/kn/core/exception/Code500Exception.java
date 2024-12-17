package com.kn.core.exception;

import com.kn.core.common.ApiStatus;

public class Code500Exception extends BaseException {
    private static final long serialVersionUID = 1L;

    public Code500Exception() {
        setCode(ApiStatus.CODE_500);
        setMsg(ApiStatus.CODE_500_MSG);
    }

    public Code500Exception(String msg) {
        setCode(ApiStatus.CODE_500);
        setMsg(msg);
    }
}