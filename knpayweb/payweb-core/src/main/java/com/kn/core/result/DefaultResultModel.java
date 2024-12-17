package com.kn.core.result;


import com.kn.core.common.ApiStatus;

import java.io.Serializable;


public class DefaultResultModel extends BaseResultModel implements Serializable{
	public  DefaultResultModel(){
		setCode(ApiStatus.CODE_200);
		setMsg(ApiStatus.CODE_200_MSG);
	}
	
	public  DefaultResultModel(String code,String msg){
		setCode(code);
		setMsg(msg);
	}
	/**
	 * 
	 */
	private static final long serialVersionUID = 638035143362903221L;
	private  Object  val;
	
	public Object getVal() {
		return val;
	}
	public void setVal(Object val) {
		this.val = val;
	}
	
	
}
