package com.kn.core.result;

import com.kn.core.common.ApiStatus;
import org.apache.commons.lang3.StringUtils;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

public class PageResultModel<T> extends BaseResultModel implements Serializable {

    /**
     *
     */
    private static final long serialVersionUID = -9020336639898577325L;

    /**
     * 数据列表
     */
    private List<T> list = new ArrayList<T>();

    /**
     * 每页显示几条记录
     */
    private Integer pageSize;


    /**
     * 第几页
     */
    private Integer pageIndex;


    /**
     * 总条数
     */
    private Long total;


    public List<T> getList() {
        return list;
    }

    public void setList(List<T> list) {
        this.list = list;
    }

    public Integer getPageSize() {
        return pageSize;
    }

    public void setPageSize(Integer pageSize) {
        this.pageSize = pageSize;
    }

    public Integer getPageIndex() {
        return pageIndex;
    }

    public void setPageIndex(Integer pageIndex) {
        this.pageIndex = pageIndex;
    }

    public Long getTotal() {
        return total;
    }

    public void setTotal(Long total) {
        this.total = total;
    }

    @Override
    public String getCode() {
        // TODO Auto-generated method stub
        return "200";
    }


    @Override
    public String getMsg() {
        String valmsg = null;
        if (msg.equals(ApiStatus.CODE_200_MSG)) {
            valmsg = ApiStatus.CODE_200_MSG;
        } else if (msg.equals(ApiStatus.CODE_500_MSG)) {
            valmsg = ApiStatus.CODE_500_MSG;
        }
        return msg;
    }


}
