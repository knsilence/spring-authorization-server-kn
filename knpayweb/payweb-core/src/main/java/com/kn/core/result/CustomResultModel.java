package com.kn.core.result;


import com.kn.core.common.ApiStatus;

import java.io.Serializable;

public class CustomResultModel extends BaseResultModel implements Serializable{

	public  CustomResultModel(){
		setCode(ApiStatus.CODE_200);
		setMsg(ApiStatus.CODE_200_MSG);
	}
	
	public  CustomResultModel(String code,String msg){
		setCode(code);
		setMsg(msg);
	}
	/**
	 * 
	 */
	private static final long serialVersionUID = 638035143362903221L;
	private  Object  val;
	
	private  Object  status;
	
	public Object getVal() {
		return val;
	}
	public void setVal(Object val) {
		this.val = val;
	}

	public Object getStatus() {
		return status;
	}

	public void setStatus(Object status) {
		this.status = status;
	}




	
	
}
