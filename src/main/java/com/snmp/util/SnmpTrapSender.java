package com.snmp.util;

import org.snmp4j.*;
import org.snmp4j.event.ResponseEvent;
import org.snmp4j.mp.MPv3;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.security.*;
import org.snmp4j.smi.*;
import org.snmp4j.transport.DefaultUdpTransportMapping;

import java.io.IOException;

public class SnmpTrapSender {

    private Snmp snmp = null;

    private Address targetAddress = null;

    private TransportMapping<UdpAddress> transport = null;

    //UsmUser 的userName
    private String username = "snmpuser";
    //认证协议的密码  如MD5
    private String authPassword = "auth123456";
    //加密协议密码  如 DES AES
    private String privPassword = "priv123456";

    public static void main(String[] args) {

        SnmpTrapSender poc = new SnmpTrapSender();

        try {
            poc.init();
           // poc.sendV1Trap();
            //poc.sendV2cTrap();
            poc.sendV3TrapNoAuthNoPriv();
            //poc.sendV3();
        } catch (IOException e) {
            e.printStackTrace();
        }

    }

    public void init() throws IOException {
        //目标主机的ip地址 和 端口号
        targetAddress = GenericAddress.parse("udp:172.16.1.37/162");
        transport = new DefaultUdpTransportMapping();
        snmp = new Snmp(transport);
        transport.listen();
    }

    /**
     * Snmp V1 测试发送Trap
     * @return
     * @throws IOException
     */
    public ResponseEvent sendV1Trap() throws IOException {
        PDUv1 pdu = new PDUv1();
        VariableBinding v = new VariableBinding();
        v.setOid(SnmpConstants.sysName);
        v.setVariable(new OctetString("Snmp Trap V1 Test"));
        pdu.add(v);
        pdu.setType(PDU.V1TRAP);

        CommunityTarget target = new CommunityTarget();
        target.setCommunity(new OctetString("public"));
        target.setAddress(targetAddress);
        target.setRetries(2);
        target.setTimeout(1500);
        target.setVersion(SnmpConstants.version1);
        return snmp.send(pdu, target);
    }

    /**
     * Snmp V2c 测试发送Trap
     * @return
     * @throws IOException
     */
    public ResponseEvent sendV2cTrap() throws IOException {

        PDU pdu = new PDU();
        VariableBinding v = new VariableBinding();
        v.setOid(SnmpConstants.sysName);
        v.setVariable(new OctetString("Snmp Trap V2 Test"));
        pdu.add(v);
        pdu.setType(PDU.TRAP);


        CommunityTarget target = new CommunityTarget();
        target.setCommunity(new OctetString("public"));
        target.setAddress(targetAddress);
        target.setRetries(2);
        target.setTimeout(1500);
        target.setVersion(SnmpConstants.version2c);
        return snmp.send(pdu, target);

    }

    /**
     * SnmpV3 不带认证加密协议.
     * @return
     * @throws IOException
     */
    public ResponseEvent sendV3TrapNoAuthNoPriv() throws IOException {
        SNMP4JSettings.setExtensibilityEnabled(true);
        SecurityProtocols.getInstance().addDefaultProtocols();

        UserTarget target = new UserTarget();
        target.setVersion(SnmpConstants.version3);

        try {
            transport = new DefaultUdpTransportMapping();
        } catch (IOException e1) {
            e1.printStackTrace();
        }

        byte[] enginId = "TEO_ID".getBytes();
        USM usm = new USM(SecurityProtocols.getInstance(), new OctetString(
                enginId), 500);
        SecurityModels secModels = SecurityModels.getInstance();
        if (snmp.getUSM() == null) {
            secModels.addSecurityModel(usm);
        }

        target.setSecurityLevel(SecurityLevel.NOAUTH_NOPRIV);
        target.setAddress(targetAddress);

        ScopedPDU pdu = new ScopedPDU();
        pdu.setType(PDU.NOTIFICATION);
        VariableBinding v = new VariableBinding();
        v.setOid(SnmpConstants.sysName);
        v.setVariable(new OctetString("Snmp Trap V3 Test sendV3TrapNoAuthNoPriv"));
        pdu.add(v);

        snmp.setLocalEngine(enginId, 500, 1);
        return snmp.send(pdu, target);
    }


    /**
     * 测试SnmpV3  带认证协议，加密协议
     * @return
     * @throws IOException
     */
    public ResponseEvent sendV3() throws IOException{
        OctetString userName = new OctetString(username);
        OctetString authPass = new OctetString(authPassword);
        OctetString privPass = new OctetString(privPassword);

        TransportMapping<?> transport;
        transport = new DefaultUdpTransportMapping();

        Snmp snmp = new Snmp(transport);
        USM usm = new USM(SecurityProtocols.getInstance(),
                new OctetString(MPv3.createLocalEngineID()), 500);
        SecurityModels.getInstance().addSecurityModel(usm);

        UserTarget target = new UserTarget();
        byte[] enginId = "TEO_ID".getBytes();
        SecurityModels secModels = SecurityModels.getInstance();
        synchronized (secModels) {
            if (snmp.getUSM() == null) {
                secModels.addSecurityModel(usm);
            }
            // add user to the USM
            snmp.getUSM().addUser(userName,new UsmUser(userName,AuthMD5.ID,authPass,PrivDES.ID,privPass));

            target.setAddress(targetAddress);
            target.setRetries(2);
            target.setTimeout(3000);
            target.setVersion(SnmpConstants.version3);
            target.setSecurityLevel(SecurityLevel.AUTH_NOPRIV);
            target.setSecurityName(userName);

            ScopedPDU pdu = new ScopedPDU();
            pdu.setType(PDU.NOTIFICATION);
            VariableBinding v = new VariableBinding();
            v.setOid(SnmpConstants.sysName);
            v.setVariable(new OctetString("Snmp Trap V3 Test sendV3Auth----------"));
            pdu.add(v);

            snmp.setLocalEngine(enginId, 500, 1);
            ResponseEvent send = snmp.send(pdu, target);

            return send;
        }

    }
}