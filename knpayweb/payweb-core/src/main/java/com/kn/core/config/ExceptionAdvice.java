package com.kn.core.config;

import com.kn.core.exception.*;
import com.kn.core.result.BaseResultModel;
import com.kn.core.result.DefaultResultModel;
import org.hibernate.exception.ConstraintViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.validation.BindException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.ResponseStatus;

@ControllerAdvice  
@ResponseBody  
public class ExceptionAdvice {
	
	
	@ExceptionHandler({
		Code404Exception.class})
	@ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
	public DefaultResultModel handleCustomException(BaseException e) {
	    DefaultResultModel result = new DefaultResultModel();
	    result.setMsg(e.getMsg());
	    result.setCode(e.getCode());
	    result.setVal(e.getVal());
	    e.printStackTrace();
	    return result;
	}
	 @ExceptionHandler(Code401Exception.class)
	 @ResponseStatus(HttpStatus.UNAUTHORIZED)
     public BaseResultModel handleCode401Exception(Code401Exception ex) {
         BaseResultModel result = new BaseResultModel();
         result.setMsg(ex.getMsg());
         result.setCode(HttpStatus.UNAUTHORIZED.value()+"");
         // 处理无效请求逻辑
         return result;
     }
	 
	 @ExceptionHandler(Code400Exception.class)
	 @ResponseStatus(HttpStatus.BAD_REQUEST)
     public BaseResultModel handleCode400Exception(Code400Exception ex) {
         BaseResultModel result = new BaseResultModel();
         result.setMsg(ex.getMsg());
         result.setCode(HttpStatus.BAD_REQUEST.value()+"");
         // 处理无效请求逻辑
         return result;
     }
	 
	 
	 @ExceptionHandler(BindException.class)
	 @ResponseStatus(HttpStatus.BAD_REQUEST)
     public BaseResultModel handleBindException(BindException ex) {
         BaseResultModel result = new BaseResultModel();
         result.setMsg(ex.getMessage());
         result.setCode(HttpStatus.BAD_REQUEST.value()+"");
         // 处理无效请求逻辑
         return result;
     }
	 
	 @ExceptionHandler(ConstraintViolationException.class)
	 @ResponseStatus(HttpStatus.BAD_REQUEST)
     public BaseResultModel handleConstraintViolationException(ConstraintViolationException ex) {
         BaseResultModel result = new BaseResultModel();
         result.setMsg(ex.getMessage());
         result.setCode(HttpStatus.BAD_REQUEST.value()+"");
         // 处理无效请求逻辑
         return result;
     }

	  
	 
	 @ExceptionHandler(Code403Exception.class)
	 @ResponseStatus(HttpStatus.FORBIDDEN)
     public BaseResultModel handleCode403Exception(Code403Exception ex) {
         BaseResultModel result = new BaseResultModel();
         result.setMsg(ex.getMsg());
         result.setCode(HttpStatus.FORBIDDEN.value()+"");
         // 处理无效请求逻辑
         return result;
     }
	 @ExceptionHandler(Code500Exception.class)
	 @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
     public BaseResultModel handleCode500Exception(Code500Exception ex) {
         BaseResultModel result = new BaseResultModel();
         result.setMsg(ex.getMsg());
         result.setCode(HttpStatus.INTERNAL_SERVER_ERROR.value()+"");
         // 处理无效请求逻辑
         return result;
     }
    }

    
    
 
    
