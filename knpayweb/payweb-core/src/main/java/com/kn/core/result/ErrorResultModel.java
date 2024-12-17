package com.kn.core.result;


import com.kn.core.common.ApiStatus;

import java.io.Serializable;

public class ErrorResultModel extends BaseResultModel implements Serializable{
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	public  ErrorResultModel(){
		setCode(ApiStatus.CODE_500);
		setMsg(ApiStatus.CODE_500_MSG);
	}
	
	public  ErrorResultModel(String code,String msg){
		setCode(code);
		setMsg(msg);
	}
	
	/**
	 * 
	 */
	private  Object  val;
	public Object getVal() {
		return val;
	}
	public void setVal(Object val) {
		this.val = val;
	}
	
}
