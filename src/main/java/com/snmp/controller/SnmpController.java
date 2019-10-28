package com.snmp.controller;

import com.snmp.util.SNMPQuery;
import com.snmp.util.SNMPTrapHandler;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.smi.OID;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@Api(tags = "Snmp测试")
public class SnmpController {


    @RequestMapping(value = "/snmpquery",method = {RequestMethod.GET})
    @ApiOperation(value = "snmp查询测试")
    public void snmpQuery(@ApiParam("代理方Ip") @RequestParam(required = true) String targetIp,
                          @ApiParam("团体名") @RequestParam(required = true) String community,
                          @ApiParam("OID") @RequestParam(required = true) String oid,
                          @ApiParam("版本号 v1=0 v2c=1 v3=3") @RequestParam(required = true) int version,
                          @ApiParam("PUD类型 0-get 1-walk") @RequestParam(required = true) int type){
        SNMPQuery snmpQuery = new SNMPQuery(targetIp,161,version,community);
        try {
            if(type == 0){
                snmpQuery.snmpGet(oid);
            }else {
                snmpQuery.snmpWalk(new OID(oid),"WALK");
            }
        }catch (Exception e){
            e.printStackTrace();
        }
    }

    @RequestMapping(value = "/snmptrap",method = {RequestMethod.GET})
    @ApiOperation(value = "启动snmptrap监听")
    public void snmpTrap(){
        SNMPTrapHandler trapReceiver = new SNMPTrapHandler(
                "172.16.1.37", 162, SnmpConstants.version3, "public");
    }

    @RequestMapping(value = "/snmpquery",method = {RequestMethod.POST})
    @ApiOperation(value = "snmp查询测试")
    public void snmpTrapSend(@ApiParam("管理方Ip") @RequestParam(required = true) String targetIp,
                          @ApiParam("团体名") @RequestParam(required = true) String community,
                          @ApiParam("OID") @RequestParam(required = true) String oid,
                          @ApiParam("版本号 v1=0 v2c=1 v3=3") @RequestParam(required = true) int version){

    }
}
