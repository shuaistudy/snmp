package com.snmp.controller;

import com.alibaba.fastjson.JSONObject;
import com.snmp.util.SNMPQuery;
import com.snmp.util.SNMPTrapHandler;
import com.snmp.util.SerialNumberUtil;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.smi.OID;
import org.springframework.web.bind.annotation.*;


@RestController
@Api(tags = "Snmp测试")
public class SnmpController {

    private SNMPQuery snmpQuery;

    private SNMPTrapHandler snmpTrapHandler;


    @RequestMapping(value = "/snmpquery",method = {RequestMethod.GET})
    @ApiOperation(value = "snmp查询测试")
    @ResponseBody
    public JSONObject snmpQuery(@ApiParam("代理方Ip") @RequestParam(required = true) String targetIp,
                       @ApiParam("团体名") @RequestParam(required = true) String community,
                       @ApiParam("OID") @RequestParam(required = true) String oid,
                       @ApiParam("版本号 v1=0 v2c=1 v3=3") @RequestParam(required = true) int version,
                       @ApiParam("PUD类型 0-get 1-walk") @RequestParam(required = true) int type){

        JSONObject datas = null;
        snmpQuery = new SNMPQuery(targetIp,161,version,community);
        try {
            if(type == 0){
                 datas = snmpQuery.snmpGet(oid);
            }else {
                 datas = snmpQuery.snmpWalk(new OID(oid),"WALK");
            }
        }catch (Exception e){
            e.printStackTrace();
        }
        return datas;
    }

    @RequestMapping(value = "/snmptrap",method = {RequestMethod.GET})
    @ApiOperation(value = "启动snmptrap监听")
    public void snmpTrap(@ApiParam("管理方Ip") @RequestParam(required = true) String hostIp,
                         @ApiParam("团体名") @RequestParam(required = true) String community){
        snmpTrapHandler = new SNMPTrapHandler(
                 hostIp, 162, SnmpConstants.version3, community);
    }

    @RequestMapping(value = "numberTest",method = {RequestMethod.GET})
    @ApiOperation(value = "获取机器序列号")
    public void NumberTest(){
        SerialNumberUtil.getAllSn();
    }
}
