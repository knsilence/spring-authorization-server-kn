package com.kn.core.exception;



public class BaseException extends RuntimeException{
	
	public  BaseException(String  code,String msg){
		this.code=code;
		this.msg=msg;
	}
	public  BaseException(){}
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	protected  String  code;
	
	protected  String  msg;
	
	protected  Object  val;
	
	

	public String getCode() {
		return code;
	}

	public void setCode(String code) {
		this.code = code;
	}

	public String getMsg() {
		return msg;
	}

	public void setMsg(String msg) {
		this.msg = msg;
	}
	public Object getVal() {
		return val;
	}
	public void setVal(Object val) {
		this.val = val;
	}
	
	
	
}
