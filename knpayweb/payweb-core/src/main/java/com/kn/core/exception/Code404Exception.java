package com.kn.core.exception;

import com.kn.core.common.ApiStatus;

public class Code404Exception extends BaseException {
    private static final long serialVersionUID = 1L;

    public Code404Exception() {
        setCode(ApiStatus.CODE_404);
        setMsg(ApiStatus.CODE_404_MSG);
    }

    public Code404Exception(String msg) {
        setCode(ApiStatus.CODE_404);
        setMsg(msg);
    }
}