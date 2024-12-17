package com.kn.core.exception;

import com.kn.core.common.ApiStatus;

/**
 * 没有访问权限
 * @author Administrator
 *
 */
public class Code403Exception extends BaseException{
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	public Code403Exception(){
		setCode(ApiStatus.CODE_403);
		setMsg(ApiStatus.CODE_403_MSG);
	}
	
	public Code403Exception(String message){
		setCode(ApiStatus.CODE_403);
		setMsg(message);
	}
}
